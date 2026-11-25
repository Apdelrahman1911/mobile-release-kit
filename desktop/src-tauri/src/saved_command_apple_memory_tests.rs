//! Actual registry/parent/Arc census with inert, unadmitted inputs. No native
//! use, runtime, source operation, provider or positive join is manufactured.
use super::*;

fn application() -> SavedCommandOwner {
    SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        "/never-opened-apple-census".into(),
    ))
}

fn input(mode: apple_wire::Mode, original: Option<Arc<OriginalWork>>) -> Arc<Input> {
    let context = Input::census_context(mode);
    let material = crate::asset_session::SelectedStoreMaterial::apple_census_data(
        &context,
        1024,
        16 * 1024,
        4096,
    );
    Input::census_data(
        context,
        material,
        crate::application_service_host::NativeStateReady::closed_apple_census_data(),
        original,
    )
}

fn review(input: &Arc<Input>) -> Arc<AppleProvisioningReview> {
    assert!(input.current().is_err() && input.ready().begin_use().is_err());
    Arc::new(AppleProvisioningReview {
        input: input.clone(),
        reference: apple_wire::Reference {
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
        },
        observed_at: "inert memory comparison".into(),
        before_sha256: "c".repeat(64),
        expires: Instant::now() + Duration::from_secs(30),
        used: AtomicBool::new(false),
    })
}

fn intent(input: Arc<Input>, review: Option<Arc<AppleProvisioningReview>>) -> Arc<Intent> {
    Arc::new(Intent { preparation:None,
        agent: std::sync::OnceLock::new(),
        witness: Arc::new(()),
        input,
        review,
        profile_review: None,
        key_review: None,
        certificate_review: None,
        p12_review: None,
    })
}

impl SavedCommandOwner {
    pub(crate) fn retain_apple_census_review_data(&self, input: &Arc<Input>) {
        assert_eq!(self.inner.domain, SavedCommandDomain::AppleProvisioning);
        let mut registry = self.inner.registry.lock().unwrap();
        assert!(registry.prepared.is_none() && registry.active.is_none());
        registry.apple.review = Some(review(input));
    }

    pub(crate) fn install_apple_census_active_data(
        &self,
        input: Arc<Input>,
        original: &Arc<OriginalWork>,
    ) {
        assert!(input.current().is_err() && input.ready().begin_use().is_err());
        assert!(self.inner.registry.lock().unwrap().active.is_none());
        let application = SavedCommandOwner {
            inner: self.inner.clone(),
        };
        let (_, mut owner) = super::super::super::tests::active_with_context(
            application,
            Context::AppleProvisioning(input.context().clone()),
        );
        // Replace only this unentered fixture's private input before creating
        // its real parent clock. No callback/task or weak Session exists yet.
        let mut active = self.inner.registry.lock().unwrap().active.take().unwrap();
        drop(active.owner);
        let old_review = self.inner.registry.lock().unwrap().apple.review.clone();
        Arc::get_mut(&mut owner).unwrap().apple = State::new(Some(intent(input, old_review)));
        if matches!(&owner.context, Context::AppleProvisioning(context) if context.mode.profile()) {
            super::super::super::apple_signing::initialize(&owner).unwrap();
            let (send, receive) = oneshot::channel();
            owner
                .apple_profile
                .get()
                .unwrap()
                .attach(original, send)
                .unwrap();
            drop(receive); // No Asset GO/worker/save command is ever sent.
        } else {
            super::super::super::apple_key::initialize(&owner).unwrap();
            let (send, receive) = oneshot::channel();
            owner
                .apple_key
                .get()
                .unwrap()
                .attach(original, send)
                .unwrap();
            drop(receive);
        }
        assert!(!owner.startup.lock().unwrap().attempted);
        assert!(
            !owner.driver_joined.load(Ordering::SeqCst)
                && !owner.watchdog_joined.load(Ordering::SeqCst)
        );
        active.owner = owner;
        self.inner.registry.lock().unwrap().active = Some(active);
    }
}

#[test]
fn empty_registry_census_is_try_only_and_does_not_poison_or_publish() {
    let owner = application();
    assert_eq!(
        owner.apple_retained_census(None).unwrap().members().count(),
        0
    );
    let guard = owner.inner.registry.lock().unwrap();
    let revision = guard.revision;
    assert!(owner.apple_retained_census(None).is_err());
    assert!(!owner.inner.poisoned.load(Ordering::SeqCst));
    drop(guard);
    assert_eq!(owner.inner.registry.lock().unwrap().revision, revision);
    assert_eq!(
        owner.apple_retained_census(None).unwrap().members().count(),
        0
    );
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner.inner.registry.lock().unwrap();
        panic!("inert registry poison");
    }));
    assert!(owner.apple_retained_census(None).is_err());
    assert!(!owner.inner.poisoned.load(Ordering::SeqCst)); // getter never mutates this fence
    assert!(CONTROL_BYTES <= 32 * 1024);
}

#[test]
fn prepared_and_consumed_review_keep_two_exact_inputs_after_registry_unlock() {
    let owner = application();
    let old = input(apple_wire::Mode::Review, None);
    let current = input(apple_wire::Mode::Review, None);
    owner.retain_apple_census_review_data(&old);
    let alias = SavedCommandOwner {
        inner: owner.inner.clone(),
    };
    let (_, session) = super::super::super::tests::active_with_context(
        alias,
        Context::AppleProvisioning(current.context().clone()),
    );
    {
        let mut registry = owner.inner.registry.lock().unwrap();
        let mut projection = registry.active.take().unwrap().projection;
        projection.phase = Phase::AwaitingConsent;
        projection.intent_usable = true;
        let old_review = registry.apple.review.clone();
        registry.prepared = Some(Prepared {
            agent_history_preparation:None, agent_history:None, agent_store_preparation: None,
            agent_store: None,
            store_witness: None,
            agent_build: None,
            agent_local_check: None,
            upload_key_preparation: None,
            upload_key: None,
            apple: Some(intent(current.clone(), old_review)),
            tools: None,
            local_history: None,
            projection,
            expires: Instant::now() + INTENT,
            registration: session.registration,
            project: session.project.clone(),
            recovery_stamp: None,
            material: None,
            recovery: None,
            android_selection: None,
            artifact_selection: None,
            artifact_tools: None,
        });
    }
    drop(session);
    let snapshot = owner.apple_retained_census(None).unwrap();
    let roots: Vec<_> = snapshot.members().map(|(input, _)| input).collect();
    assert_eq!(roots.len(), 2);
    assert!(roots.iter().any(|input| Arc::ptr_eq(input, &old)));
    assert!(roots.iter().any(|input| Arc::ptr_eq(input, &current)));
    let guard = owner
        .inner
        .registry
        .try_lock()
        .expect("snapshot must not retain registry guard");
    assert!(guard.active.is_none() && guard.prepared.is_some());
    drop(guard);
    assert!(old.current().is_err() && current.current().is_err());
}

#[test]
fn active_census_requires_same_parent_and_asset_including_key_recover() {
    for mode in [
        apple_wire::Mode::ProfileReview,
        apple_wire::Mode::KeyReview,
        apple_wire::Mode::KeyRecover,
        apple_wire::Mode::CertificateReview,
        apple_wire::Mode::P12Review,
    ] {
        let owner = application();
        let original = OriginalWork::artifact_unentered_original_data();
        let current = input(mode, Some(original.clone()));
        owner.install_apple_census_active_data(current.clone(), &original);
        let snapshot = owner.apple_retained_census(Some(&original)).unwrap();
        assert_eq!(snapshot.members().count(), 1);
        assert!(snapshot
            .members()
            .all(|(input, held)| Arc::ptr_eq(input, &current)
                && held.is_some_and(|held| Arc::ptr_eq(held, &original))));
        let foreign = OriginalWork::artifact_unentered_original_data(); // same DATA id, different Arc
        assert!(owner.apple_retained_census(Some(&foreign)).is_err());
        assert_eq!(
            owner.apple_retained_census(None).err().unwrap().code,
            "apple_provisioning_busy"
        );
        let registry = owner.inner.registry.lock().unwrap();
        let active = registry.active.as_ref().unwrap();
        assert!(
            !registry.disabled
                && !registry.stopping
                && active.first_stop.is_none()
                && !active.unknown
        );
        assert!(!*active.owner.stop.borrow());
        assert!(
            !active.owner.driver_joined.load(Ordering::SeqCst)
                && !active.owner.watchdog_joined.load(Ordering::SeqCst)
        );
        assert!(!owner.inner.poisoned.load(Ordering::SeqCst));
    }
    let owner = application();
    let parent_original = OriginalWork::artifact_unentered_original_data();
    let other_input_original = OriginalWork::artifact_unentered_original_data();
    owner.install_apple_census_active_data(
        input(apple_wire::Mode::KeyRecover, Some(other_input_original)),
        &parent_original,
    );
    assert!(owner.apple_retained_census(Some(&parent_original)).is_err());
}

#[test]
fn third_distinct_retained_input_is_refused_not_omitted() {
    let inputs = [
        input(apple_wire::Mode::Review, None),
        input(apple_wire::Mode::Review, None),
        input(apple_wire::Mode::Review, None),
    ];
    let mut snapshot = Snapshot::new();
    snapshot.add(&inputs[0]).unwrap();
    snapshot.add(&inputs[0]).unwrap();
    snapshot.add(&inputs[1]).unwrap();
    assert_eq!(snapshot.members().count(), 2);
    assert!(snapshot.add(&inputs[2]).is_err());
    assert_eq!(snapshot.members().count(), 2);
    assert!(inputs
        .iter()
        .all(|input| input.current().is_err() && input.ready().begin_use().is_err()));
}

#[test]
fn retained_quote_keeps_original_buffers_and_only_replaces_absent_material_reservation() {
    let common = store::document_backing_bytes().unwrap()
        + APPLE_PROVISIONING_INPUT_LIMIT
        + 2 * apple_wire::STATUS_LIMIT
        + recovery_backing_bytes().unwrap()
        + 8192
        + 16 * 1024;
    assert_eq!(
        retained_document_backing_bytes(),
        Some(common + CONTROL_BYTES)
    );
    assert!(CONTROL_BYTES > 0 && CONTROL_BYTES <= 32 * 1024);
    let old = common + 6 * 1024 * 1024;
    assert_eq!(
        old - retained_document_backing_bytes().unwrap(),
        6 * 1024 * 1024 - CONTROL_BYTES
    );
}
