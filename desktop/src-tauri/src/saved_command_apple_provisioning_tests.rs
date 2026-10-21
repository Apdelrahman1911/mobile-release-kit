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

#[test]
fn certificate_history_requires_original_entered_returned_key_ack_not_completed_data() {
    let state = State::new(None);
    assert!(!state.certificate_key_returned());
    {
        let mut route = state.route.lock().unwrap();
        route.received = 1;
        route.ack_entered[0] = true;
    }
    assert!(!state.certificate_key_returned()); // Entered/partial is not returned.
    state.route.lock().unwrap().completed = 1;
    assert!(state.certificate_key_returned()); // Only this original route factor, NOT all-jobs finality.
    for field in 0..4 {
        let mut route = state.route.lock().unwrap();
        match field { 0 => route.ack_writing = true, 1 => route.failed = true,
            2 => route.received = 2, _ => route.ack_entered[0] = false }
        drop(route);
        assert!(!state.certificate_key_returned());
        let mut route = state.route.lock().unwrap();
        route.ack_writing = false; route.failed = false; route.received = 1; route.ack_entered[0] = true;
    }
    let held = state.route.lock().unwrap();
    assert!(!state.certificate_key_returned()); // Never wait/reborrow the route under a publication guard.
    drop(held);
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
    RunProjection { agent_build: None, agent_local_check: None,
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
    assert!(retained >= APPLE_PROVISIONING_INPUT_LIMIT + 2 * apple_wire::STATUS_LIMIT);
    let common = document_backing_bytes(apple_wire::Mode::Review).unwrap();
    let modes = [
        apple_wire::Mode::Review, apple_wire::Mode::Register, apple_wire::Mode::Reconcile,
        apple_wire::Mode::ProfileReview, apple_wire::Mode::ProfileReuse,
        apple_wire::Mode::ProfileCreate, apple_wire::Mode::ProfileReconcile,
        apple_wire::Mode::KeyReview, apple_wire::Mode::KeyPrepare, apple_wire::Mode::KeyRecover,
        apple_wire::Mode::CertificateReview, apple_wire::Mode::CertificateCreate,
        apple_wire::Mode::CertificateReconcile,
        apple_wire::Mode::P12Review, apple_wire::Mode::P12Reuse, apple_wire::Mode::P12Save,
    ];
    // Print every branch before any fit assertion: one failing mode must not
    // hide the distinct selected-P12 or private-save quote in a native run.
    let quotes: Vec<_> = modes.into_iter().map(|mode| {
        let active = document_backing_bytes(mode).unwrap();
        let input = 2 * private_input_backing_bytes(mode);
        eprintln!("Apple owner DATA quote: mode={mode:?}; retained={retained}; active={active}; private_input_overlap={input}; total={}; cap={}",
            retained.checked_add(active).unwrap(), 64 * 1024 * 1024);
        (mode, active)
    }).collect();
    for (mode, active) in quotes {
        // Mirror the actual initialize branches, not a max of mutually
        // exclusive sessions. All common retained/state/ACK backing remains;
        // only Certificate/P12 active wire and private-input sizes differ.
        let parent = match mode {
            apple_wire::Mode::Review | apple_wire::Mode::Register | apple_wire::Mode::Reconcile => 0,
            apple_wire::Mode::ProfileReview | apple_wire::Mode::ProfileReuse
            | apple_wire::Mode::ProfileCreate | apple_wire::Mode::ProfileReconcile =>
                super::super::apple_signing::backing_bytes().unwrap(),
            apple_wire::Mode::KeyReview | apple_wire::Mode::KeyPrepare | apple_wire::Mode::KeyRecover
            | apple_wire::Mode::CertificateReview | apple_wire::Mode::CertificateCreate
            | apple_wire::Mode::CertificateReconcile
            | apple_wire::Mode::P12Review | apple_wire::Mode::P12Reuse | apple_wire::Mode::P12Save =>
                super::super::apple_key::backing_bytes(mode).unwrap(),
        };
        let original = common.checked_add(parent).unwrap();
        let expected = if mode.certificate() || mode.p12() {
            let unused_wire = 4 * (apple_wire::PROFILE_IDENTITY_LIMIT
                + apple_wire::PROFILE_JSON_LIMIT + apple_wire::KEY_JSON_LIMIT);
            original.checked_sub(unused_wire).unwrap()
                .checked_sub(2 * (4 * 1024 * 1024 + 4096 + 16 * 1024 + 46)).unwrap()
                .checked_add(2 * private_input_backing_bytes(mode)).unwrap()
        } else { original };
        assert_eq!(active, expected, "{mode:?}");
        assert!(active >= 8 * crate::apple_provisioning_journal::STATE_LIMIT, "{mode:?}");
        assert!(active.checked_add(retained).unwrap() < 64 * 1024 * 1024, "{mode:?}");
        assert!(active.checked_add(usize::MAX).is_none(), "{mode:?}");
    }
    assert_eq!(2 * private_input_backing_bytes(apple_wire::Mode::CertificateCreate), 57_436);
    assert_eq!(2 * private_input_backing_bytes(apple_wire::Mode::P12Save), 57_564);
    assert_eq!(2 * private_input_backing_bytes(apple_wire::Mode::P12Review), 8_454_236);
    assert_eq!(private_input_backing_bytes(apple_wire::Mode::P12Reuse),
        private_input_backing_bytes(apple_wire::Mode::P12Review));
    // This is a fixed representation census only, not a native/RSS bound.
}

#[test]
fn apple_start_parent_dispatch_matches_actual_initialized_modes() {
    use apple_wire::Mode;
    fn scope(mode: Mode) -> apple_wire::Context {
        let mut scope = context();
        scope.mode = mode;
        scope.new_application = mode == Mode::Register;
        if !matches!(mode, Mode::Review | Mode::ProfileReview | Mode::KeyReview
            | Mode::CertificateReview | Mode::P12Review)
        {
            scope.reference = Some(apple_wire::Reference {
                operation_id: "d".repeat(32), owner_generation: "e".repeat(32),
            });
        }
        if mode.profile() || mode == Mode::P12Reuse {
            scope.p12_record_id = Some("f".repeat(32));
            scope.p12_record_revision = Some(1);
        }
        if mode.certificate() || mode.p12() {
            scope.key_record_id = Some("1".repeat(32));
            scope.key_record_revision = Some(1);
        }
        scope
    }
    let fixture = |mode| {
        let context = scope(mode);
        assert!(context.valid());
        let (application, original) = super::super::tests::active_with_context(
            SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
                std::path::PathBuf::from("/unopened-apple-start-parent-runtime"),
            )),
            Context::AppleProvisioning(context),
        );
        assert!(original.apple_profile.get().is_none() && original.apple_key.get().is_none());
        super::super::apple_signing::initialize(&original).unwrap();
        super::super::apple_key::initialize(&original).unwrap();
        (application, original)
    };
    // Genuine constructor-only parents provide wrong-family/extra-parent
    // negatives; no native input, loan, ticket or joined receipt is invented.
    let (_profile_owner, profile_original) = fixture(Mode::ProfileReview);
    let (_key_owner, key_original) = fixture(Mode::KeyReview);
    for (mode, needs_profile, needs_key) in [
        (Mode::Review, false, false), (Mode::Register, false, false), (Mode::Reconcile, false, false),
        (Mode::ProfileReview, true, false), (Mode::ProfileReuse, true, false),
        (Mode::ProfileCreate, true, false), (Mode::ProfileReconcile, true, false),
        (Mode::KeyReview, false, true), (Mode::KeyPrepare, false, true),
        (Mode::CertificateReview, false, true), (Mode::CertificateCreate, false, true),
        (Mode::CertificateReconcile, false, true), (Mode::P12Review, false, true),
        (Mode::P12Reuse, false, true), (Mode::P12Save, false, true),
    ] {
        let (_application, original) = fixture(mode);
        let profile = original.apple_profile.get();
        let key = original.apple_key.get();
        assert_eq!((profile.is_some(), key.is_some()), (needs_profile, needs_key), "{mode:?}");
        assert!(admitted_parents_match(mode, profile, key), "{mode:?}");
        for (has_profile, has_key) in [(false, false), (true, false), (false, true), (true, true)] {
            let profile = has_profile.then(|| profile.or(profile_original.apple_profile.get()).unwrap());
            let key = has_key.then(|| key.or(key_original.apple_key.get()).unwrap());
            assert_eq!(admitted_parents_match(mode, profile, key),
                (has_profile, has_key) == (needs_profile, needs_key), "{mode:?}");
        }
        if mode.p12() {
            assert_eq!(key.unwrap().p12_mode(), Some(mode));
        }
        assert!(!original.startup.lock().unwrap().attempted);
        assert!(!original.driver_joined.load(Ordering::SeqCst));
        assert!(!original.watchdog_joined.load(Ordering::SeqCst));
        assert!(!native_complete(&original));
    }
    assert!(!scope(Mode::KeyRecover).valid());
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
    assert!(!original.driver_joined.load(Ordering::SeqCst));
    // This inert original selected no private material. Its vacuous material
    // retirement is not a worker/watchdog/native join or recovery authority.
    assert!(original.material.lock().unwrap().is_none());
    assert!(original.material_retired.load(Ordering::SeqCst));
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


#[test]
fn apple_original_terminal_dispatch_uses_the_retained_profile_mode() {
    // Exercise the SAME enum method used by enqueue/final disposition. The
    // serialized lifetime is invented DATA; it cannot create native joins.
    let Some(Terminal::AppleProvisioning(original)) = projection().result else {
        panic!("fixture terminal")
    };
    let baseline = serde_json::to_value(original).unwrap();
    for (mode, profile) in [
        ("review", false), ("register", false), ("reconcile", false),
        ("profile-review", true), ("profile-reuse", true),
        ("profile-create", true), ("profile-reconcile", true),
    ] {
        for calls in 0..=2 {
            let mut value = baseline.clone();
            value["context"]["mode"] = json!(mode);
            value["lifetime"]["profileCalls"] = json!(calls);
            let terminal: apple_wire::Terminal = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(terminal.settled(), calls <= u32::from(profile));
            assert_eq!(Terminal::AppleProvisioning(terminal).settled(), calls <= u32::from(profile));
            for missing in ["complete", "contained", "inputClosed", "handlersRestored", "invocationClosed"] {
                let mut incomplete = value.clone();
                incomplete["lifetime"][missing] = json!(false);
                let terminal: apple_wire::Terminal = serde_json::from_value(incomplete).unwrap();
                assert!(!Terminal::AppleProvisioning(terminal).settled());
            }
        }
    }
}

#[test]
fn apple_original_store_closure_keeps_mode_and_owner_gates() {
    use apple_wire::Mode;
    // These existing inert Sessions and typed frames exercise the actual
    // Store closure predicate, not a native runtime or positive join receipt.
    for (mode, permits_profile_call) in [
        (Mode::Review, false),
        (Mode::Register, false),
        (Mode::Reconcile, false),
        (Mode::ProfileReview, true),
        (Mode::ProfileReuse, true),
        (Mode::ProfileCreate, true),
        (Mode::ProfileReconcile, true),
        (Mode::KeyReview, false),
        (Mode::KeyPrepare, false),
        (Mode::CertificateReview, false),
        (Mode::CertificateCreate, false),
        (Mode::CertificateReconcile, false),
        (Mode::P12Review, true),
        (Mode::P12Reuse, true),
        (Mode::P12Save, true),
    ] {
        let mut scope = context();
        scope.mode = mode;
        scope.new_application = mode == Mode::Register;
        if !matches!(mode, Mode::Review | Mode::ProfileReview | Mode::KeyReview
            | Mode::CertificateReview | Mode::P12Review)
        {
            scope.reference = Some(apple_wire::Reference {
                operation_id: "d".repeat(32), owner_generation: "e".repeat(32),
            });
        }
        if mode.profile() || mode == Mode::P12Reuse {
            scope.p12_record_id = Some("f".repeat(32));
            scope.p12_record_revision = Some(1);
        }
        if mode.certificate() || mode.p12() {
            scope.key_record_id = Some("1".repeat(32));
            scope.key_record_revision = Some(1);
        }
        assert!(scope.valid());
        for calls in 0..=2 {
            let fixture = || super::super::tests::active_with_context(
                SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
                    std::path::PathBuf::from("/unopened-apple-store-closure-runtime"),
                )),
                Context::AppleProvisioning(scope.clone()),
            );
            let (application, original) = fixture();
            let (_foreign_application, foreign) = fixture();
            let at = original.clocks.admitted;
            {
                let registry = application.inner.lock();
                assert!(!store::closure_ready(&registry, &original, true, true));
                // The original unclaimed/no-child branch still needs its
                // direct-return input and exact Session, never a terminal.
                assert!(store::closure_ready(&registry, &original, false, true));
                assert!(!store::closure_ready(&registry, &original, false, false));
                assert!(!store::closure_ready(&registry, &foreign, false, true));
            }
            application.inner.accept_at(
                &original, Frame::AppleProvisioning(apple_wire::Frame::Accepted), at,
            );
            assert!(!store::closure_ready(&application.inner.lock(), &original, true, true));
            let terminal: apple_wire::Terminal = serde_json::from_value(json!({
                "schemaVersion":1,"context":scope,"outcome":"cancelled","reason":"cancelled","result":null,
                "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":7,
                    "profileCalls":calls,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"cancelled"}
            })).unwrap();
            application.inner.accept_at(
                &original, Frame::AppleProvisioning(apple_wire::Frame::Terminal(terminal)), at,
            );
            let expected = calls <= u32::from(permits_profile_call);
            let mut registry = application.inner.lock();
            assert_eq!(store::closure_ready(&registry, &original, true, true), expected,
                "mode {mode:?}, profile calls {calls}");
            assert!(!store::closure_ready(&registry, &original, true, false));
            // Same public IDs/context in another original owner are not the
            // original Session, even when its terminal DATA would match.
            assert!(!store::closure_ready(&registry, &foreign, true, true));
            registry.active.as_mut().unwrap().accepted = false;
            assert!(!store::closure_ready(&registry, &original, true, true));
            registry.active.as_mut().unwrap().accepted = true;
            registry.active.as_mut().unwrap().terminal = false;
            assert!(!store::closure_ready(&registry, &original, true, true));
            registry.active.as_mut().unwrap().terminal = true;
            assert_eq!(store::closure_ready(&registry, &original, true, true), expected);
            assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(at));
            assert!(*original.stop.borrow());
            assert!(!original.startup.lock().unwrap().attempted);
            assert!(!original.driver_joined.load(Ordering::SeqCst));
            assert!(!original.watchdog_joined.load(Ordering::SeqCst));
            assert!(!native_complete(&original));
        }
    }
}

#[test]
fn profile_original_clock_and_preasset_refusal_do_not_invent_completion() {
    let mut scope = context();
    scope.mode = apple_wire::Mode::ProfileReview;
    scope.p12_record_id = Some("d".repeat(32));
    scope.p12_record_revision = Some(1);
    let application = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-profile-clock-runtime"),
    ));
    let (application, original) = super::super::tests::active_with_context(
        application, Context::AppleProvisioning(scope),
    );
    super::super::apple_signing::initialize(&original).unwrap();
    let profile = original.apple_profile.get().unwrap();
    assert_eq!(profile.clock().work_end(), original.clocks.work);
    assert_eq!(profile.clock().hard_end(), original.clocks.cleanup);
    let first = original.clocks.admitted + Duration::from_secs(3);
    let later = first + Duration::from_secs(2);
    {
        let mut registry = application.inner.lock();
        application.inner.stop_locked(&mut registry, &original, Reason::Cancelled, first);
        application.inner.stop_locked(&mut registry, &original, Reason::Shutdown, later);
    }
    assert_eq!(profile.clock().failure().unwrap().1, first);
    assert_eq!(profile.clock().cleanup_end(), first + SETTLEMENT);
    assert_eq!(*original.native_audit_cutoff.borrow(), first + SETTLEMENT);
    assert!(!profile.clock().completed());
    profile.decline_before_asset(crate::asset_commands::Reason::UserCancelled, later).unwrap();
    assert!(profile.decline_before_asset(crate::asset_commands::Reason::UserCancelled, later).is_err());
    assert!(!profile.clock().completed());
    assert_eq!(profile.clock().failure().unwrap().1, first);
    assert!(!native_complete(&original));
    assert!(!original.driver_joined.load(Ordering::SeqCst));
    assert!(!original.watchdog_joined.load(Ordering::SeqCst));
    let registry = application.inner.lock();
    let mut publication = Registry::default();
    retire_review(&mut publication, registry.active.as_ref().unwrap(), &original);
    assert!(publication.profile_review.is_none() && publication.profile_saved.is_none());
}
