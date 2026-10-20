//! Original memory-only owner/clock and projection tests. Invented terminal
//! DATA never enters a native Session or creates a key, Store/NativeUse,
//! OriginalReservation, join witness, installed runtime or provider permit.
use super::*;
use serde_json::json;

fn context() -> apple_wire::Context {
    apple_wire::prepare(&json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
        "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
        "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,"executionMode":"local","platform":"ios",
        "mode":"review","reference":null,"newApplication":false,"displayName":"Explicit name"})).unwrap().context
}

fn projection() -> RunProjection {
    let context = context();
    let terminal: apple_wire::Terminal = serde_json::from_value(json!({
        "schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-ios-bundle-provisioning","mode":"review",
            "observation":"not-returned","decision":"review-required","attempt":null,"comparison":null,
            "limitations":["bundle-id-only","no-release-or-signing-readiness","no-certificate-or-profile-changes",
                "no-team-verification","no-global-availability-claim","one-write-no-retry","parent-journal-and-native-joins-required"]},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":7,
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}
    })).unwrap();
    RunProjection { agent_local_check: None,
        operation_id: "d".repeat(32),
        owner_generation: "e".repeat(32),
        context: Context::AppleProvisioning(context),
        phase: Phase::Terminal,
        intent_usable: false,
        outcome: Some(Outcome::Complete),
        reason: Reason::None,
        result: Some(Terminal::AppleProvisioning(terminal)),
        stage: None,
    }
}

#[test]
fn apple_original_clock_and_finite_representation_quote_are_not_renewed() {
    let now = Instant::now();
    let clocks = Clocks::new(SavedCommandDomain::AppleProvisioning, now);
    assert_eq!(clocks.work - now, Duration::from_secs(1200));
    assert_eq!(clocks.finality - now, Duration::from_secs(1210));
    let first = now + Duration::from_secs(12);
    assert_eq!(clocks.settlement(Some(first)), first + SETTLEMENT);
    assert!(clocks.settlement(Some(clocks.work + Duration::from_secs(9))) <= clocks.finality);
    let retained = retained_document_backing_bytes().unwrap();
    let active = document_backing_bytes().unwrap();
    assert!(retained >= APPLE_PROVISIONING_INPUT_LIMIT + 2 * apple_wire::STATUS_LIMIT);
    assert!(active >= 8 * crate::apple_provisioning_journal::STATE_LIMIT);
    assert!(active.checked_add(retained).unwrap() < 16 * 1024 * 1024);
    // This is a fixed representation census only, not a native/RSS bound.
}

#[test]
fn apple_original_session_stop_tightens_audit_and_preserves_earliest_failure() {
    for reason in [Reason::Cancelled, Reason::ContextChanged, Reason::Shutdown] {
        // The existing parent helper installs only an inert original Session.
        // There is no native state token, process, journal or joined receipt.
        let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
            std::path::PathBuf::from("/unopened-apple-provisioning-stop-runtime"),
        ));
        let (application, original) = super::super::tests::active_with_context(
            application,
            Context::AppleProvisioning(context()),
        );
        let audit = original.native_audit_cutoff.subscribe();
        let cleanup = original.native_cleanup_cutoff.subscribe();
        let admitted = original.clocks.admitted;
        let first = admitted + Duration::from_secs(5);
        let earlier = admitted + Duration::from_secs(2);
        let later = admitted + Duration::from_secs(8);
        assert_eq!(*audit.borrow(), original.clocks.work);
        let mut registry = application.inner.lock();
        application
            .inner
            .stop_locked(&mut registry, &original, reason, first);
        assert_eq!(*audit.borrow(), first + SETTLEMENT);
        assert_eq!(*cleanup.borrow(), first + SETTLEMENT);
        assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(first));
        assert!(*original.stop.borrow());
        // A later observation cannot move F; an earlier captured failure can
        // tighten it even if its Registry publication arrives afterward.
        application
            .inner
            .stop_locked(&mut registry, &original, Reason::JournalUnavailable, later);
        assert_eq!(*audit.borrow(), first + SETTLEMENT);
        application
            .inner
            .stop_locked(&mut registry, &original, Reason::ContextChanged, earlier);
        assert_eq!(*audit.borrow(), earlier + SETTLEMENT);
        assert_eq!(*cleanup.borrow(), earlier + SETTLEMENT);
        application.inner.stop_locked(
            &mut registry,
            &original,
            Reason::TimedOut,
            original.clocks.work,
        );
        assert_eq!(*audit.borrow(), earlier + SETTLEMENT);
        assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(earlier));
        assert!(original.native_failure.lock().unwrap().is_none());
        assert!(!original.driver_joined.load(Ordering::SeqCst));
        assert!(!original.watchdog_joined.load(Ordering::SeqCst));
    }
    // At the end of work the audit endpoint is W, not a renewed F+10.
    let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-apple-provisioning-work-runtime"),
    ));
    let (application, original) = super::super::tests::active_with_context(
        application,
        Context::AppleProvisioning(context()),
    );
    let mut registry = application.inner.lock();
    application.inner.stop_locked(
        &mut registry,
        &original,
        Reason::Cancelled,
        original.clocks.work - Duration::from_secs(1),
    );
    assert_eq!(*original.native_audit_cutoff.borrow(), original.clocks.work);
    assert_eq!(
        *original.native_cleanup_cutoff.borrow(),
        original.clocks.work + Duration::from_secs(9)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[test]
fn apple_original_unknown_and_shutdown_veto_both_independent_document_gates() {
    for unknown in [false, true] {
        let (bridge, document) = super::super::tests::bound_document_model();
        if unknown {
            let (application, original) = super::super::tests::active_with_context(
                bridge.apple_provisioning.clone(),
                Context::AppleProvisioning(context()),
            );
            assert!(Arc::ptr_eq(
                &application.inner,
                &bridge.apple_provisioning.inner
            ));
            // The existing reconciliation observes genuinely absent original
            // handles, not a fabricated positive join, and retains Unknown.
            assert!(!application.can_exit());
            assert!(application.disabled());
            assert!(!original.driver_joined.load(Ordering::SeqCst));
        } else {
            bridge.apple_provisioning.request_shutdown();
            assert!(bridge.apple_provisioning.stopping());
        }
        // Both public methods call their own original closed Document gate.
        // Unknown/Shutdown must precede Linux's UnsupportedPlatform refusal;
        // no test claims the unavailable native Busy/Available branch works.
        assert_eq!(
            document.tool_acquisition_status().unwrap().availability,
            if unknown {
                tools_wire::Availability::CleanupUnknown
            } else {
                tools_wire::Availability::Shutdown
            }
        );
        assert_eq!(
            document
                .local_release_history_status()
                .unwrap()
                .availability,
            if unknown {
                history_wire::Availability::CleanupUnknown
            } else {
                history_wire::Availability::Shutdown
            }
        );
    }
}

#[test]
fn apple_projection_hides_child_data_until_original_terminal_complete() {
    let baseline = projection();
    // This positive branch tests only DATA projection, never native authority.
    assert!(baseline.clone().public().apple().unwrap().result.is_some());
    for phase in [
        Phase::AwaitingConsent,
        Phase::Starting,
        Phase::Running,
        Phase::Stopping,
        Phase::Unknown,
    ] {
        let mut value = baseline.clone();
        value.phase = phase;
        assert!(value.public().apple().unwrap().result.is_none());
    }
    for outcome in [
        None,
        Some(Outcome::Refused),
        Some(Outcome::Failed),
        Some(Outcome::Cancelled),
        Some(Outcome::TimedOut),
        Some(Outcome::Unknown),
    ] {
        let mut value = baseline.clone();
        value.outcome = outcome;
        assert!(value.public().apple().unwrap().result.is_none());
    }
    for reason in [
        Reason::ContextChanged,
        Reason::JournalUnavailable,
        Reason::CleanupUnknown,
        Reason::Cancelled,
    ] {
        let mut value = baseline.clone();
        value.reason = reason;
        assert!(value.public().apple().unwrap().result.is_none());
    }
}

#[test]
fn historical_projection_requires_the_exact_complete_review_and_never_mints_consent() {
    // Only the private cached DATA projection is exercised positively here.
    // No test creates the original retirement, NativeUse or a Register review.
    let (account, scope) = apple_wire::recovery_comparison_fixture();
    let baseline = projection();
    let Context::AppleProvisioning(context) = &baseline.context else { panic!("fixture context") };
    let mut registry = Registry::default();
    registry.recovery = Some(RecoveryPublication {
        reference: apple_wire::Reference {
            operation_id: baseline.operation_id.clone(), owner_generation: baseline.owner_generation.clone(),
        }, context: context.clone(), history: apple_wire::recovery_history(&account, &scope).unwrap(),
    });
    let mut projected = baseline.clone().public().apple().unwrap();
    project_recovery(&registry, &mut projected);
    assert!(projected.recovery.is_some() && registry.review.is_none());
    for field in 0..8 {
        let mut value = baseline.clone();
        match field {
            0 => value.operation_id = "1".repeat(32),
            1 => value.owner_generation = "2".repeat(32),
            2 => value.phase = Phase::Running,
            3 => value.phase = Phase::Unknown,
            4 => value.outcome = Some(Outcome::Failed),
            5 => value.reason = Reason::ContextChanged,
            6 => { let Context::AppleProvisioning(c) = &mut value.context else { unreachable!() }; c.mode = apple_wire::Mode::Reconcile; }
            _ => { let Context::AppleProvisioning(c) = &mut value.context else { unreachable!() }; c.record_revision += 1; }
        }
        let mut projected = value.public().apple().unwrap();
        project_recovery(&registry, &mut projected);
        assert!(projected.recovery.is_none() && registry.review.is_none());
    }
    invalidate_review(&mut registry);
    let mut projected = baseline.public().apple().unwrap();
    project_recovery(&registry, &mut projected);
    assert!(projected.recovery.is_none());
}

#[test]
fn original_idle_context_loss_withdraws_only_history_and_advances_status() {
    let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-apple-history-withdrawal-runtime"),
    ));
    let (account, scope) = apple_wire::recovery_comparison_fixture();
    let baseline = projection();
    let Context::AppleProvisioning(context) = &baseline.context else { panic!("fixture context") };
    {
        // Stored projection DATA only; no original operation, join witness,
        // material loan, Register review or native-positive fixture is created.
        let mut registry = application.inner.lock();
        registry.apple.recovery = Some(RecoveryPublication {
            reference: apple_wire::Reference {
                operation_id: baseline.operation_id.clone(), owner_generation: baseline.owner_generation.clone(),
            }, context: context.clone(), history: apple_wire::recovery_history(&account, &scope).unwrap(),
        });
        registry.last = Some(baseline);
    }
    let before = application.status_apple_provisioning(apple_wire::Availability::Busy).unwrap();
    assert!(before.operation.as_ref().unwrap().recovery.is_some());
    application.context_changed();
    let after = application.status_apple_provisioning(apple_wire::Availability::Busy).unwrap();
    assert!(after.status_revision > before.status_revision);
    assert!(after.operation.as_ref().unwrap().recovery.is_none());
    assert_eq!(serde_json::to_value(before.operation.as_ref().unwrap().result.as_ref()).unwrap(),
        serde_json::to_value(after.operation.as_ref().unwrap().result.as_ref()).unwrap());
    let registry = application.inner.lock();
    assert!(registry.prepared.is_none() && registry.active.is_none() && registry.apple.review.is_none());
}

#[test]
fn original_unjoined_session_cannot_publish_history_or_restore_a_review() {
    let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-apple-history-runtime"),
    ));
    let (application, original) = super::super::tests::active_with_context(application, Context::AppleProvisioning(context()));
    let parent = application.inner.lock();
    let active = parent.active.as_ref().unwrap();
    let mut registry = Registry::default();
    retire_review(&mut registry, active, &original);
    assert!(registry.recovery.is_none() && registry.review.is_none());
    assert!(!original.watchdog_joined.load(Ordering::SeqCst));
    assert!(!original.material_retired.load(Ordering::SeqCst));
    assert!(!native_complete(&original));
}

#[test]
fn apple_unadmitted_original_status_cannot_start_state_or_borrow_access_consent() {
    let owner = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-apple-provisioning-runtime"),
    ));
    for _ in 0..2 {
        let status = owner
            .status_apple_provisioning(apple_wire::Availability::Busy)
            .unwrap();
        assert!(status.operation.is_none());
        assert!(status.availability != apple_wire::Availability::Available);
        assert!(owner
            .prepared_apple_provisioning_input(&"a".repeat(32), &"b".repeat(32))
            .is_err());
    }
    assert!(owner
        .status_store(store_wire::Availability::Available)
        .is_err());
    assert!(owner
        .cancel_apple_provisioning(
            &"a".repeat(32),
            &"b".repeat(32),
            apple_wire::Availability::Busy
        )
        .is_err());
    let registry = owner.inner.lock();
    assert!(registry.prepared.is_none() && registry.active.is_none() && registry.last.is_none());
    assert!(registry.apple.review.is_none());
}
