//! Actual closed wire, retirement projection and finite inbox/Read/Claim paths.
//! Synthetic DATA only: no source census, native Prepare permit, tool process,
//! saved file, provider, download or positive runtime qualification is made.
use super::*;

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn context() -> wire::Context {
    wire::prepare(
        &serde_json::json!({"projectId":"p1","draftRevision":1,"baselineGeneration":2,
        "savedConfig":{"bytes":120,"sha256":"a".repeat(64)},"action":"inspect","review":null}),
    )
    .unwrap()
}
fn review() -> p::Review {
    p::Review {
        kind: p::Kind::InspectSavedRequirements,
        platform: p::Platform::Android,
        draft_revision: 1,
        baseline_generation: 2,
        prepared: None,
        sources: None,
        acquisition: None,
    }
}
fn scope(doc: &Arc<()>, now: Instant, selected: p::Review) -> Arc<req::NativeScope> {
    Arc::new(req::NativeScope {
        project_id: id('1'),
        runtime_id: "p1".into(),
        review_id: id('4'),
        review: selected,
        root: "/inert-never-opened-tool-inspect".into(),
        device: 1,
        inode: 2,
        observation_revision: 1,
        saved_config: Some(crate::agent_local_checks::Config {
            bytes: 120,
            sha256: "a".repeat(64),
        }),
        expires: now + Duration::from_secs(60),
        read: Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                now + Duration::from_secs(80),
            ),
        ),
        document: Arc::downgrade(doc),
        control: req::Control::new(),
        retired: AtomicBool::new(false),
        changes: watch::channel(0).0,
    })
}

#[test]
fn saved_inspect_wire_keeps_required_nulls_and_cannot_request_acquisition() {
    let expected = review();
    let value = serde_json::to_value(&expected).unwrap();
    assert!(expected.valid());
    assert_eq!(
        expected.kind.action(),
        crate::service_protocol::Action::ObserveProject
    );
    assert_eq!(expected.kind.consent(), "agent-tool-inspect-saved-once-v1");
    for field in ["prepared", "sources"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<p::Review>(missing).is_err());
    }
    for (field, bad) in [
        (
            "prepared",
            serde_json::json!({"operationId":id('a'),"ownerGeneration":id('b'),"statusRevision":1}),
        ),
        (
            "sources",
            serde_json::json!({"registrationGeneration":1,"sourceGeneration":2,"reviewId":null}),
        ),
        ("platform", serde_json::json!("ios")),
    ] {
        let mut other = value.clone();
        other[field] = bad;
        assert!(!serde_json::from_value::<p::Review>(other).unwrap().valid());
    }
    let mut extra = value.clone();
    extra["path"] = "/never-authority".into();
    assert!(serde_json::from_value::<p::Review>(extra).is_err());
    for kind in [p::Kind::InspectRequirements, p::Kind::AcquireMissing] {
        let mut old = expected.clone();
        old.kind = kind;
        assert!(!old.valid()); // Existing actions still require their real Prepared.
    }
    let report = p::Report::InspectSavedRequirements {
        missing: vec![p::Component::Jdk],
    };
    assert!(report.valid_for(&expected));
    assert!(!p::Report::AcquireMissing {
        staged: vec![p::Component::Jdk]
    }
    .valid_for(&expected));
    assert!(!p::Report::InspectRequirements {
        missing: vec![p::Component::Jdk]
    }
    .valid_for(&expected));
    assert!(!p::Report::InspectSavedRequirements {
        missing: vec![p::Component::Jdk, p::Component::Jdk]
    }
    .valid_for(&expected));
    let mut missing_review = serde_json::to_value(context()).unwrap();
    missing_review.as_object_mut().unwrap().remove("review");
    assert!(wire::prepare(&missing_review).is_err());
}

#[test]
fn later_preparation_cannot_renew_original_allow_read_or_first_failure() {
    let now = Instant::now();
    let doc = Arc::new(());
    for selected in [review(), acquire_review()] {
    let original = scope(&doc, now, selected);
    let later = now + Duration::from_secs(300);
    assert_eq!(
        clipped_end(later, later, &original, now).unwrap(),
        original.expires
    );
    let approved = now + Duration::from_secs(50);
    assert_eq!(
        clipped_end(later, approved, &original, now).unwrap(),
        approved
    );
    let earlier_prepared = now + Duration::from_secs(20);
    assert_eq!(
        clipped_end(earlier_prepared, approved, &original, now).unwrap(),
        earlier_prepared
    );
    assert!(clipped_end(later, approved, &original, approved).is_err());
    original.control.stop(p::Reason::PermissionRevoked, now);
    assert!(clipped_end(later, later, &original, now).is_err());
    assert_eq!(
        original.control.first().unwrap(),
        Some((p::Reason::PermissionRevoked, now))
    );
    }
}

#[test]
fn prepared_retirement_keeps_identity_before_start_and_waits_caller_and_history() {
    for selected in [review(), acquire_review()] {
    for caller_first in [false, true] {
        let now = Instant::now();
        let doc = Arc::new(());
        let s = scope(&doc, now, selected.clone());
        let mut context = context();
        if let Some(a) = &selected.acquisition { context.action = wire::Action::Acquire; context.review = Some(wire::Review {
            operation_id:a.operation_id.as_str().into(),owner_generation:a.owner_generation.as_str().into(),requirements_sha256:a.requirements_sha256.clone() }); }
        let inbox = req::Inbox::new(id('2'));
        inbox.allow(s.clone(), id('3')).unwrap();
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
                now,
            )
            .unwrap();
        let entry = inbox.entries().unwrap()[0].clone();
        let link = req::NativeLink::new(s.clone());
        link.attach(&entry).unwrap();
        let mut caller = Some(inbox.claim().unwrap().unwrap());
        let b = super::super::Binding {
            approval: Arc::new(super::super::Approval {
                owner: Weak::new(),
                intent: Weak::new(),
                context: context.clone(),
                registration: 1,
                root: RegisteredRoot {
                    path: s.root.clone(),
                    identity: crate::asset_source::ProjectIdentity::Posix(
                        crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
                    ),
                },
                expires: s.read.end(),
                review: selected.clone(),
            }),
            link: link.clone(),
        };
        let prepared = RunProjection {
            agent_build: None,
            agent_local_check: None,
            operation_id: id('a').as_str().into(),
            owner_generation: id('b').as_str().into(),
            context: Context::ToolAcquisition(context),
            phase: Phase::AwaitingConsent,
            intent_usable: true,
            outcome: None,
            reason: Reason::None,
            result: None,
            stage: None,
        };
        // Same private terminal mapping used by retire_prepared after an
        // actual Prepare commit. No Session or entered receipt is fabricated.
        link.cancel(p::Reason::PermissionRevoked, now);
        if caller_first {
            caller.take().unwrap().returned();
        }
        assert!(!link.has_entered());
        super::super::retired_projection(&b, &retire(prepared, Reason::Cancelled));
        let pending = entry.status().unwrap();
        assert_eq!(pending.operation.unwrap().operation_id, id('a'));
        assert_eq!(pending.state, p::State::Finishing);
        assert!(entry.pending());
        if !caller_first {
            assert!(entry.claim_history().unwrap().is_none());
            caller.take().unwrap().returned();
        }
        let history = entry.claim_history().unwrap().unwrap();
        assert!(history.first && entry.pending());
        history.returned(Ok(())).unwrap();
        let final_status = entry.status().unwrap();
        assert_eq!(final_status.state, p::State::Cancelled);
        assert_eq!(final_status.reason, p::Reason::PermissionRevoked);
        assert_eq!(final_status.outcome, Some(p::Outcome::Cancelled));
        assert!(final_status.result.is_none() && !entry.pending());
        assert!(!link.has_entered() && link.caller_returned());
        assert!(inbox.claim().unwrap().is_none());
    }
    }
}

fn acquire_review() -> p::Review {
    serde_json::from_value(serde_json::json!({"kind":"acquire-reviewed-missing","platform":"android","draftRevision":1,"baselineGeneration":2,
        "prepared":null,"sources":null,"acquisition":{"operationId":id('c'),"ownerGeneration":id('d'),"requirementsSha256":"b".repeat(64),
            "missing":["android-build-tools"],"compatible":["jdk","android-platform","gradle"]}})).unwrap()
}

#[test]
fn first_start_source_cut_refuses_foreign_entry_without_retiring_prepared_or_borrowing_sources() {
    for selected in [review(), acquire_review()] {
        let now = Instant::now();
        let doc = Arc::new(());
        let scope = scope(&doc, now, selected.clone());
        let submit = p::Submit {
            origin: p::Query { project_id: id('1'), service_instance: id('2'), request_id: id('5') },
            grant_id: id('3'), review_id: id('4'),
        };
        let inbox = req::Inbox::new(id('2'));
        inbox.allow(scope.clone(), id('3')).unwrap();
        inbox.submit(submit.clone(), now).unwrap();
        let entry = inbox.entries().unwrap()[0].clone();
        let link = req::NativeLink::new(scope.clone());
        link.attach(&entry).unwrap();
        let other = req::Inbox::new(id('2'));
        other.allow(scope.clone(), id('3')).unwrap();
        other.submit(submit, now).unwrap();
        let foreign = other.entries().unwrap()[0].clone();
        assert_eq!(entry.status().unwrap(), foreign.status().unwrap());
        assert!(!Arc::ptr_eq(&entry, &foreign));
        // SAME comparator used by both early source lookup and final Start.
        // Matching this reference is not consume(), entered or a native join.
        assert!(super::super::start_origin_matches(None, None));
        assert!(!super::super::start_origin_matches(None, Some(&entry)));
        assert!(!super::super::start_origin_matches(Some(&link), None));
        assert!(super::super::start_origin_matches(Some(&link), Some(&entry)));
        assert!(!super::super::start_origin_matches(Some(&link), Some(&foreign)));

        let owner = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged("/never-opened-first-tool-start".into()));
        let mut context = context();
        if let Some(a) = &selected.acquisition {
            context.action = wire::Action::Acquire;
            context.review = Some(wire::Review { operation_id: a.operation_id.as_str().into(),
                owner_generation: a.owner_generation.as_str().into(), requirements_sha256: a.requirements_sha256.clone() });
        }
        let expires = now + INTENT;
        owner.inner.lock().prepared = Some(Prepared {
            agent_history_preparation: None, agent_history: None, agent_store_preparation: None, agent_store: None, store_witness: None,
            agent_build: None, agent_local_check: None, upload_key_preparation: None, upload_key: None,
            apple: None, tools: None, local_history: None,
            projection: RunProjection { agent_build: None, agent_local_check: None,
                operation_id: id('a').as_str().into(), owner_generation: id('b').as_str().into(),
                context: Context::ToolAcquisition(context.clone()), phase: Phase::AwaitingConsent,
                intent_usable: true, outcome: None, reason: Reason::None, result: None, stage: None },
            expires, registration: 1,
            project: RegisteredRoot { path: scope.root.clone(), identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
            recovery_stamp: None, material: None, recovery: None, android_selection: None,
            artifact_selection: None, artifact_tools: None,
        });
        // A real current Prepared slot, deliberately with no Tool Intent or
        // CatalogLoan. Do not fabricate positive source authority to test a
        // losing caller. The opposite linked-GUI case is covered above.
        for candidate in [Some(&entry), Some(&foreign), None] {
            assert!(owner.prepared_tool_acquisition_document(id('a').as_str(), id('b').as_str(), candidate).is_err());
            let registry = owner.inner.lock();
            let prepared = registry.prepared.as_ref().unwrap();
            assert_eq!(registry.revision, 0);
            assert!(registry.active.is_none() && registry.last.is_none());
            assert_eq!(prepared.projection.context, Context::ToolAcquisition(context.clone()));
            assert!(prepared.projection.intent_usable && prepared.tools.is_none());
            assert_eq!(prepared.expires, expires);
            assert_eq!(super::super::start_matches(prepared, candidate), candidate.is_none());
        }
        assert!(!link.has_entered());
        assert!(scope.control.first().unwrap().is_none());
    }
}
