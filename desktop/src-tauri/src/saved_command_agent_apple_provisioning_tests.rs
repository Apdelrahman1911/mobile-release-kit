//! Original facet methods with inert bounded DATA. No native/runtime/Store/
//! Asset/NativeUse join or permission is constructed by these tests.
use super::*;
fn id(c: char) -> s::Id {
    s::Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn context() -> apple_wire::Context {
    apple_wire::prepare(&serde_json::json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
        "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
        "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,"executionMode":"local","platform":"ios",
        "mode":"review","reference":null,"newApplication":false,"displayName":"Explicit name"})).unwrap().context
}
fn projected() -> RunProjection {
    RunProjection {
        agent_build: None,
        agent_local_check: None,
        operation_id: id('a').as_str().into(),
        owner_generation: id('b').as_str().into(),
        context: Context::AppleProvisioning(context()),
        phase: Phase::Terminal,
        intent_usable: false,
        outcome: Some(Outcome::Cancelled),
        reason: Reason::Cancelled,
        result: None,
        stage: None,
    }
}
#[test]
fn apple_cli_modes_are_closed_and_key_recover_requires_prepared_context() {
    use apple_wire::Mode as M;
    for m in [
        M::Review,
        M::Register,
        M::Reconcile,
        M::ProfileReview,
        M::ProfileReuse,
        M::ProfileCreate,
        M::ProfileReconcile,
        M::KeyReview,
        M::KeyPrepare,
        M::CertificateReview,
        M::CertificateCreate,
        M::CertificateReconcile,
        M::P12Review,
        M::P12Reuse,
        M::P12Save,
    ] {
        let mut c = context();
        c.mode = m;
        c.new_application = m == M::Register;
        if !matches!(
            m,
            M::Review | M::ProfileReview | M::KeyReview | M::CertificateReview | M::P12Review
        ) {
            c.reference = Some(apple_wire::Reference {
                operation_id: id('d').as_str().into(),
                owner_generation: id('e').as_str().into(),
            });
        }
        if m.profile() || m == M::P12Reuse {
            c.p12_record_id = Some(id('f').as_str().into());
            c.p12_record_revision = Some(1)
        }
        if m.certificate() || m.p12() {
            c.key_record_id = Some(id('1').as_str().into());
            c.key_record_revision = Some(1)
        }
        assert!(c.valid(), "{m:?}");
        let start = apple_wire::start(&serde_json::json!({
            "operationId": id('a').as_str(),
            "ownerGeneration": id('b').as_str(),
            "consentVersion": m.consent(),
        })).unwrap();
        assert!(start.matches_context(&c));
        let r = review(
            &Context::AppleProvisioning(c),
            id('a').as_str(),
            id('b').as_str(),
            3,
        )
        .unwrap();
        assert_eq!(r.mode, mode(m).unwrap());
        assert!(r.mode.consent().starts_with("agent-apple-"));
    }
    let mut c = context();
    c.mode = M::KeyRecover;
    assert!(!c.valid());
    assert_eq!(mode(c.mode).unwrap(), p::Mode::KeyRecover);
}
#[test]
fn apple_cli_terminal_data_alone_does_not_project_native_retirement() {
    let mut p = projected();
    let r = review(&p.context, id('a').as_str(), id('b').as_str(), 1).unwrap();
    let c = requests::Control::new();
    let n = projection(&p, 2, false, &r, &c, None).unwrap();
    assert!(!n.retired);
    assert!(n.outcome.is_none());
    assert!(n.result.is_none());
    assert!(n.record_at_completion.is_none());
    let n = projection(&p, 2, true, &r, &c, None).unwrap();
    assert!(n.retired);
    assert_eq!(n.outcome, Some(p::Outcome::Cancelled));
    p.phase = Phase::Unknown;
    assert!(projection(&p, 3, true, &r, &c, None).is_err());
}
fn link() -> (Arc<Binding>, requests::Inbox, Arc<()>) {
    let p = projected();
    let r = review(&p.context, id('a').as_str(), id('b').as_str(), 1).unwrap();
    let w = Arc::new(());
    let doc = Arc::new(());
    let now = Instant::now();
    let expiry = now + Duration::from_secs(100);
    let scope = Arc::new(requests::NativeScope {
        project_id: id('1'),
        runtime_id: "fixture".into(),
        review_id: id('a'),
        review: r.clone(),
        root: "/never-opened-apple-cli".into(),
        device: 1,
        inode: 2,
        observation_revision: 1,
        expires: expiry,
        read: Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                expiry + Duration::from_secs(600),
            ),
        ),
        document: Arc::downgrade(&doc),
        witness: Arc::downgrade(&w),
        control: requests::Control::new(),
        retired: AtomicBool::new(false),
        changes: watch::channel(0).0,
    });
    let approval = Arc::new(Approval {
        owner: Weak::new(),
        intent: Weak::new(),
        witness: Arc::downgrade(&w),
        material: Weak::new(),
        project: "fixture".into(),
        registration: 1,
        root: RegisteredRoot {
            path: scope.root.clone(),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        },
        expires: expiry,
        review: r,
    });
    let b = Arc::new(Binding {
        approval,
        scope: scope.clone(),
        _witness: w,
        entry: OnceLock::new(),
        latest: Mutex::new(None),
        consumed: AtomicBool::new(false),
    });
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
                review_id: id('a'),
            },
            now,
        )
        .unwrap();
    (b, inbox, doc)
}
#[test]
fn apple_cli_late_link_attach_preserves_original_callback_and_all_return_barriers() {
    let (b, inbox, _doc) = link();
    let entry = inbox.entries().unwrap().remove(0);
    let claim = inbox.claim().unwrap().unwrap();
    b.publish(&projected(), 2, true, None);
    assert!(entry.status().unwrap().outcome.is_none());
    b.attach(&entry).unwrap();
    assert!(entry.pending());
    assert!(b.attach(&entry).is_err());
    assert!(entry.claim_history().unwrap().is_none());
    claim.returned();
    let h = entry.claim_history().unwrap().unwrap();
    assert!(entry.pending());
    h.returned(Ok(())).unwrap();
    assert_eq!(entry.status().unwrap().state, p::State::Cancelled);
    // No native input was fabricated; Weak approval cannot reopen one.
    assert!(b.approval.input().is_err());
}
#[test]
fn apple_cli_consumed_read_expiry_still_tightens_original_clock_after_stop() {
    let (b, _inbox, _doc) = link();
    let start = Instant::now();
    let clocks = Clocks::new(SavedCommandDomain::AppleProvisioning, start);
    assert_eq!(clocks.work - start, Duration::from_secs(1200));
    assert_eq!(clocks.finality - start, Duration::from_secs(1210));
    b.consumed.store(true, Ordering::Release);
    assert!(b
        .stop_at(b.scope.expires + Duration::from_secs(1))
        .is_none()); // unused-intent cap is not run expiry.
    let first = start + Duration::from_secs(10);
    b.cancel(p::Reason::UserCancelled, first);
    let earlier = start + Duration::from_secs(2);
    b.scope.read.revoke(earlier);
    assert_eq!(b.stop_at(first), Some((Reason::Cancelled, earlier)));
    assert_eq!(clocks.settlement(Some(earlier)), earlier + SETTLEMENT);
}
#[test]
fn apple_cli_original_validated_result_is_redacted_not_signing_readiness() {
    let c = context();
    let r = review(
        &Context::AppleProvisioning(c.clone()),
        id('a').as_str(),
        id('b').as_str(),
        1,
    )
    .unwrap();
    let value = serde_json::json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-ios-bundle-provisioning","mode":"review","observation":"not-returned","decision":"review-required","attempt":null,"comparison":null,
        "limitations":["bundle-id-only","no-release-or-signing-readiness","no-certificate-or-profile-changes","no-team-verification","no-global-availability-claim","one-write-no-retry","parent-journal-and-native-joins-required"]},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":7,"profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}});
    let t: apple_wire::Terminal = serde_json::from_value(value).unwrap();
    assert_eq!(t.mode(), apple_wire::Mode::Review);
    let mut other_mode = r.clone();
    other_mode.mode = p::Mode::ProfileReview;
    assert!(report(&Terminal::AppleProvisioning(t.clone()), &other_mode).is_err());
    let result = report(&Terminal::AppleProvisioning(t), &r).unwrap();
    assert_eq!(result.decision, "review-required");
    assert!(!result.credential_ready);
    assert!(result.do_not_replay);
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 7);
    assert!(value.get("context").is_none());
}
