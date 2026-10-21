//! Closed preparation origin, distinct from the existing one-use Start binding.
//! The only construction callback is at the common Saved Prepared commit.
use super::*;
use crate::service_apple_provisioning_requests::preparation::Entry;
use std::sync::Weak;

enum Prior {
    None,
    Bundle(Weak<AppleProvisioningReview>),
    Profile(Weak<profile_review::Review>),
    Key(Weak<key_review::Review>),
    Certificate(Weak<certificate_review::Review>),
    P12(Weak<p12_review::Review>),
}
pub(crate) struct Selection {
    context: apple_wire::Context,
    prior: Prior,
    expires: Instant,
    witness: Arc<()>,
}
impl Selection {
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn witness(&self) -> Weak<()> {
        Arc::downgrade(&self.witness)
    }
    fn matches(&self, i: &Intent) -> bool {
        if i.input.context() != &self.context || Instant::now() >= self.expires {
            return false;
        }
        match &self.prior {
            Prior::None => {
                i.review.is_none()
                    && i.profile_review.is_none()
                    && i.key_review.is_none()
                    && i.certificate_review.is_none()
                    && i.p12_review.is_none()
            }
            Prior::Bundle(w) => i
                .review
                .as_ref()
                .is_some_and(|r| w.as_ptr() == Arc::as_ptr(r)),
            Prior::Profile(w) => i
                .profile_review
                .as_ref()
                .is_some_and(|r| w.as_ptr() == Arc::as_ptr(r)),
            Prior::Key(w) => i
                .key_review
                .as_ref()
                .is_some_and(|r| w.as_ptr() == Arc::as_ptr(r)),
            Prior::Certificate(w) => i
                .certificate_review
                .as_ref()
                .is_some_and(|r| w.as_ptr() == Arc::as_ptr(r)),
            Prior::P12(w) => i
                .p12_review
                .as_ref()
                .is_some_and(|r| w.as_ptr() == Arc::as_ptr(r)),
        }
    }
}
pub(crate) struct Link {
    pub(crate) entry: Arc<Entry>,
    selection: Arc<Selection>,
}
impl Link {
    pub(crate) fn new(
        entry: Arc<Entry>,
        selection: Arc<Selection>,
    ) -> Result<Arc<Self>, BridgeError> {
        if entry.scope.witness.as_ptr() != Arc::as_ptr(&selection.witness)
            || agent::mode(selection.context.mode)? != entry.scope.mode
        {
            return Err(apple_wire::invalid());
        }
        Ok(Arc::new(Self { entry, selection }))
    }
    pub(in crate::saved_command_owner) fn current(&self) -> Result<(), BridgeError> {
        self.entry.current().map_err(|_| apple_wire::invalid())
    }
}
/// Fully captured Intent, not a callback or generic factory. The delegated
/// caller passes this through the existing common constructor exactly once.
pub(in crate::saved_command_owner) struct Commit {
    pub(in crate::saved_command_owner) intent: Arc<Intent>,
}
impl Commit {
    pub(in crate::saved_command_owner) fn admit(
        &self,
        context: &Context,
        registration: u32,
        root: &RegisteredRoot,
        expires: Instant,
    ) -> Result<Instant, BridgeError> {
        let i = &self.intent;
        let link = i.preparation.as_ref().ok_or_else(apple_wire::invalid)?;
        link.current()?;
        if context != &Context::AppleProvisioning(i.input.context().clone())
            || !i.input.matches(i.input.context(), registration, root)
            || !link.selection.matches(i)
        {
            return Err(apple_wire::invalid());
        }
        Ok(intent_expiry(i, expires)
            .min(link.selection.expires)
            .min(link.entry.scope.expires))
    }
    pub(in crate::saved_command_owner) fn committed(
        &self,
        p: &Prepared,
        revision: u32,
    ) -> Result<(), BridgeError> {
        let i = p
            .apple
            .as_ref()
            .filter(|i| Arc::ptr_eq(i, &self.intent))
            .ok_or_else(apple_wire::invalid)?;
        let review = agent::review(
            &p.projection.context,
            &p.projection.operation_id,
            &p.projection.owner_generation,
            revision,
        )?;
        i.preparation
            .as_ref()
            .ok_or_else(apple_wire::invalid)?
            .entry
            .constructed(review)
            .map_err(|_| apple_wire::invalid())
    }
}
/// Actual common Prepared assignment. A delegated Intent is installed before
/// its construction receipt and before the caller's existing bump/snapshot.
/// Keeping this closed commit together also lets DATA fixtures exercise the
/// publication order without creating a Host Ready or entering an executor.
pub(in crate::saved_command_owner) fn commit_prepared(
    inner: &super::super::Inner,
    registry: &mut super::super::Registry,
    prepared: Prepared,
    commit: Option<&Commit>,
) -> Result<(), BridgeError> {
    registry.prepared = Some(prepared);
    if let Some(commit) = commit {
        let next = registry
            .revision
            .checked_add(1)
            .filter(|n| *n < u32::MAX)
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if let Err(error) = commit.committed(
            registry
                .prepared
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?,
            next,
        ) {
            inner.retire_prepared(registry, Reason::CleanupUnknown);
            return Err(error);
        }
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn intent_expiry(i: &Intent, mut expires: Instant) -> Instant {
    if let Some(r) = &i.review {
        expires = expires.min(r.expires);
    }
    if let Some(r) = &i.profile_review {
        expires = expires.min(r.expires());
    }
    if let Some(r) = &i.key_review {
        expires = expires.min(r.expires());
    }
    if let Some(r) = &i.certificate_review {
        expires = expires.min(r.expires());
    }
    if let Some(r) = &i.p12_review {
        expires = expires.min(r.expires());
    }
    expires
}
pub(in crate::saved_command_owner) fn current_ready(p: &Prepared) -> bool {
    p.apple
        .as_ref()
        .and_then(|i| i.preparation.as_ref())
        .is_none_or(|l| l.entry.current_ready())
}
pub(in crate::saved_command_owner) fn start_matches(
    p: &Prepared,
    entry: Option<&Arc<crate::service_apple_provisioning_requests::Entry>>,
) -> bool {
    let Some(link) = p.apple.as_ref().and_then(|i| i.preparation.as_ref()) else {
        return true;
    };
    if entry.is_some() {
        link.entry.completed()
            && link.entry.scope.start_handed_off()
            && p.apple.as_ref().is_some_and(|i| i.agent.get().is_some())
    } else {
        link.entry.current_ready()
    }
}
pub(in crate::saved_command_owner) fn consume_gui(p: &Prepared) -> Result<(), BridgeError> {
    if p.apple.as_ref().is_some_and(|i| i.agent.get().is_some()) {
        return Ok(());
    }
    if let Some(l) = p.apple.as_ref().and_then(|i| i.preparation.as_ref()) {
        l.entry.claim_gui().map_err(|_| apple_wire::invalid())?;
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn consume_reviews(p: &Prepared) -> Result<(), BridgeError> {
    let Some(i) = &p.apple else {
        return Ok(());
    };
    consume_gui(p)?;
    if let Some(r) = &i.review {
        r.claim(&i.input, Instant::now())?;
    }
    if let Some(r) = &i.profile_review {
        r.claim(&i.input, Instant::now())?;
    }
    if let Some(r) = &i.key_review {
        r.claim(&i.input, Instant::now())?;
    }
    if let Some(r) = &i.certificate_review {
        r.claim(&i.input, Instant::now())?;
    }
    if let Some(r) = &i.p12_review {
        r.claim(&i.input, Instant::now())?;
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn retired(p: &Prepared) {
    if let Some(l) = p.apple.as_ref().and_then(|i| i.preparation.as_ref()) {
        l.entry.scope.retired();
    }
}
pub(in crate::saved_command_owner) fn stopped(p: &Prepared) -> Option<Reason> {
    let link = p.apple.as_ref()?.preparation.as_ref()?;
    if link.entry.scope.released() {
        return None;
    }
    let _ = link.entry.current();
    match link.entry.scope.first() {
        Err(_) => Some(Reason::CleanupUnknown),
        Ok(Some((r, _))) => Some(agent::native_reason(r)),
        _ => None,
    }
}
impl SavedCommandOwner {
    pub(crate) fn apple_prepare_selection(
        &self,
        context: &apple_wire::Context,
    ) -> Result<Arc<Selection>, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        agent::mode(context.mode)?;
        if !context.valid() {
            return Err(apple_wire::invalid());
        }
        self.ensure_idle()?;
        let r = self.inner.lock();
        let mut expires = Instant::now() + INTENT;
        let prior = match context.mode {
            apple_wire::Mode::Register => {
                let v = r
                    .apple
                    .review
                    .as_ref()
                    .filter(|v| Some(&v.reference) == context.reference.as_ref())
                    .ok_or_else(apple_wire::invalid)?;
                expires = expires.min(v.expires);
                Prior::Bundle(Arc::downgrade(v))
            }
            apple_wire::Mode::ProfileReuse | apple_wire::Mode::ProfileCreate => {
                let v = r
                    .apple
                    .profile_review
                    .as_ref()
                    .filter(|v| Some(&v.data().reference) == context.reference.as_ref())
                    .ok_or_else(apple_wire::invalid)?;
                expires = expires.min(v.expires());
                Prior::Profile(Arc::downgrade(v))
            }
            apple_wire::Mode::KeyPrepare => {
                let v = r
                    .apple
                    .key_review
                    .as_ref()
                    .filter(|v| Some(&v.data().reference) == context.reference.as_ref())
                    .ok_or_else(apple_wire::invalid)?;
                expires = expires.min(v.expires());
                Prior::Key(Arc::downgrade(v))
            }
            apple_wire::Mode::CertificateCreate => {
                let v = r
                    .apple
                    .certificate_review
                    .as_ref()
                    .filter(|v| Some(&v.data().reference) == context.reference.as_ref())
                    .ok_or_else(apple_wire::invalid)?;
                expires = expires.min(v.expires());
                Prior::Certificate(Arc::downgrade(v))
            }
            apple_wire::Mode::P12Reuse | apple_wire::Mode::P12Save => {
                let v = r
                    .apple
                    .p12_review
                    .as_ref()
                    .filter(|v| Some(&v.data().reference) == context.reference.as_ref())
                    .ok_or_else(apple_wire::invalid)?;
                expires = expires.min(v.expires());
                Prior::P12(Arc::downgrade(v))
            }
            _ => Prior::None,
        };
        if Instant::now() >= expires {
            return Err(apple_wire::invalid());
        }
        Ok(Arc::new(Selection {
            context: context.clone(),
            prior,
            expires,
            witness: Arc::new(()),
        }))
    }
    pub(crate) fn publish_apple_prepare(&self, entry: &Arc<Entry>) -> Result<(), BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        let Some(p) = r.prepared.as_mut().filter(|p| {
            p.apple
                .as_ref()
                .and_then(|i| i.preparation.as_ref())
                .is_some_and(|l| Arc::ptr_eq(&l.entry, entry))
        }) else {
            return Ok(());
        };
        if entry.current_ready() && !p.projection.intent_usable {
            p.projection.intent_usable = true;
            self.inner.bump(&mut r);
        }
        Ok(())
    }
    pub(crate) fn stop_apple_prepare(
        &self,
        entry: &Arc<Entry>,
        reason: crate::service_apple_provisioning_protocol::Reason,
        at: Instant,
    ) {
        entry.scope.stop(reason, at);
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_session::AppleProvisioningDocumentInput as Input,
        service_apple_provisioning_prepare_protocol as wire,
        service_apple_provisioning_protocol as p,
        service_apple_provisioning_requests::{preparation::Scope, Inbox},
        service_protocol::Id,
    };

    fn id(c: char) -> Id {
        Id::parse(&c.to_string().repeat(32)).unwrap()
    }
    struct Fixture {
        owner: SavedCommandOwner,
        input: Arc<Input>,
        entry: Arc<Entry>,
        commit: Commit,
        prepared: Option<Prepared>,
        _doc: Arc<()>,
    }
    impl Fixture {
        fn new() -> Self {
            let owner = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
                "/never-opened-apple-prepare-runtime".into(),
            ));
            let context = Input::census_context(apple_wire::Mode::Review);
            let selection = owner.apple_prepare_selection(&context).unwrap();
            let material =
                crate::asset_session::SelectedStoreMaterial::apple_census_data(&context, 32, 32, 0);
            let input = Input::census_data(
                context.clone(),
                material,
                crate::application_service_host::NativeStateReady::closed_apple_census_data(),
                None,
            );
            assert!(input.current().is_err() && input.ready().begin_use().is_err());
            let doc = Arc::new(());
            let now = Instant::now();
            let point = crate::agent_local_checks::SavedPoint {
                project_id: id('1'),
                runtime_id: context.project_id.clone(),
                root: "/never-opened-apple-prepare-project".into(),
                device: 1,
                inode: 2,
                revision: 1,
                fresh: true,
                config: Some(crate::agent_local_checks::Config {
                    bytes: context.saved_config.bytes,
                    sha256: context.saved_config.sha256.clone(),
                }),
            };
            let scope = Scope::new(
                point,
                id('4'),
                p::Mode::Review,
                selection.expires(),
                Arc::new(
                    crate::service_version_reserve_requests::ReadPermission::new(
                        now + Duration::from_secs(3600),
                    ),
                ),
                Arc::downgrade(&doc),
                selection.witness(),
                tokio::sync::watch::channel(0).0,
            )
            .unwrap();
            let inbox = Inbox::new(id('2'));
            inbox.allow_preparation(scope, id('3')).unwrap();
            let args = wire::Submit {
                origin: p::Query {
                    project_id: id('1'),
                    service_instance: id('2'),
                    request_id: id('5'),
                },
                grant_id: id('3'),
                scope_id: id('4'),
            };
            inbox.submit_preparation(args.clone(), now).unwrap();
            let entry = inbox.preparation(&args.origin).unwrap();
            let link = Link::new(entry.clone(), selection).unwrap();
            let intent = Arc::new(Intent {
                preparation: Some(link),
                agent: std::sync::OnceLock::new(),
                witness: Arc::new(()),
                input: input.clone(),
                review: None,
                profile_review: None,
                key_review: None,
                certificate_review: None,
                p12_review: None,
            });
            let alias = SavedCommandOwner {
                inner: owner.inner.clone(),
            };
            let (_, session) = crate::saved_command_owner::tests::active_with_context(
                alias,
                Context::AppleProvisioning(context),
            );
            assert!(!session.startup.lock().unwrap().attempted);
            assert!(
                !session.driver_joined.load(Ordering::SeqCst)
                    && !session.watchdog_joined.load(Ordering::SeqCst)
            );
            let mut r = owner.inner.registry.lock().unwrap();
            let mut projection = r.active.take().unwrap().projection;
            projection.phase = Phase::AwaitingConsent;
            projection.intent_usable = false;
            let prepared = Prepared {
                agent_store_preparation: None,
                agent_store: None,
                store_witness: None,
                agent_build: None,
                agent_local_check: None,
                upload_key_preparation: None,
                upload_key: None,
                apple: Some(intent.clone()),
                tools: None,
                local_history: None,
                projection,
                expires: entry.scope.expires,
                registration: session.registration,
                project: session.project.clone(),
                recovery_stamp: None,
                material: None,
                recovery: None,
                android_selection: None,
                artifact_selection: None,
                artifact_tools: None,
            };
            drop(r);
            drop(session);
            Self {
                owner,
                input,
                entry,
                commit: Commit { intent },
                prepared: Some(prepared),
                _doc: doc,
            }
        }
        fn install(&mut self) {
            let mut r = self.owner.inner.lock();
            commit_prepared(
                &self.owner.inner,
                &mut r,
                self.prepared.take().unwrap(),
                Some(&self.commit),
            )
            .unwrap();
            self.owner.inner.bump(&mut r);
        }
    }
    #[test]
    fn delegated_common_prepared_commit_never_publishes_before_real_caller_and_history() {
        let mut f = Fixture::new();
        let call = f.entry.begin().unwrap();
        f.entry.host_entered().unwrap();
        f.install();
        assert!(f.entry.claim_history().unwrap().is_none());
        f.owner.publish_apple_prepare(&f.entry).unwrap();
        assert!(
            !f.owner
                .inner
                .lock()
                .prepared
                .as_ref()
                .unwrap()
                .projection
                .intent_usable
        );
        call.returned(true).unwrap();
        f.owner.publish_apple_prepare(&f.entry).unwrap();
        assert!(
            !f.owner
                .inner
                .lock()
                .prepared
                .as_ref()
                .unwrap()
                .projection
                .intent_usable
        );
        f.entry
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        f.owner.publish_apple_prepare(&f.entry).unwrap();
        let r = f.owner.inner.lock();
        let p = r.prepared.as_ref().unwrap();
        assert!(p.projection.intent_usable && current_ready(p));
        assert!(Arc::ptr_eq(p.apple.as_ref().unwrap(), &f.commit.intent));
        assert!(p.apple.as_ref().unwrap().agent.get().is_none());
        assert!(r.active.is_none());
        drop(r);
        assert!(f.input.current().is_err() && f.input.ready().begin_use().is_err());
        // Constructor-only Input never becomes a real source/admission from
        // the metadata publication. The common admit still refuses it.
        let r = f.owner.inner.lock();
        let p = r.prepared.as_ref().unwrap();
        assert!(f
            .commit
            .admit(&p.projection.context, p.registration, &p.project, p.expires)
            .is_err());
    }
    #[test]
    fn delegated_common_commit_foreign_intent_or_lost_history_cannot_enable_start() {
        for foreign in [false, true] {
            let mut f = Fixture::new();
            let call = f.entry.begin().unwrap();
            f.entry.host_entered().unwrap();
            if foreign {
                f.prepared.as_mut().unwrap().apple = None;
                let mut r = f.owner.inner.lock();
                assert!(commit_prepared(
                    &f.owner.inner,
                    &mut r,
                    f.prepared.take().unwrap(),
                    Some(&f.commit)
                )
                .is_err());
                assert!(r.prepared.is_none() && r.active.is_none());
                drop(r);
                drop(call);
            } else {
                f.install();
                call.returned(true).unwrap();
                drop(f.entry.claim_history().unwrap().unwrap());
                f.owner.publish_apple_prepare(&f.entry).unwrap();
                assert!(f.owner.inner.lock().prepared.is_none());
            }
            assert!(!f.entry.current_ready());
            assert!(f.entry.pending());
            assert_eq!(f.entry.status().unwrap().phase, wire::Phase::Unknown);
        }
    }
    #[test]
    fn delegated_gui_start_uses_actual_before_take_handoff_but_inert_material_still_refuses() {
        let mut f = Fixture::new();
        let call = f.entry.begin().unwrap();
        f.entry.host_entered().unwrap();
        f.install();
        let ids = {
            let r = f.owner.inner.lock();
            let p = r.prepared.as_ref().unwrap();
            (
                p.projection.operation_id.clone(),
                p.projection.owner_generation.clone(),
            )
        };
        let start = || Start {
            operation_id: ids.0.clone(),
            owner_generation: ids.1.clone(),
        };
        // A real Start call cannot consume the unpublished preparation.
        assert!(f
            .owner
            .start_bound(start(), Instant::now(), None, Availability::Available, None)
            .is_err());
        assert!(f.owner.inner.lock().prepared.is_some());
        call.returned(true).unwrap();
        f.entry
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        f.owner.publish_apple_prepare(&f.entry).unwrap();
        let result = f
            .owner
            .start_bound(start(), Instant::now(), None, Availability::Available, None)
            .unwrap();
        assert!(result.release.is_none()); // no executor/source/Host/NativeUse is made
        let r = f.owner.inner.lock();
        assert!(r.prepared.is_none() && r.active.is_none());
        assert!(r.last.as_ref().unwrap().outcome != Some(Outcome::Complete));
        drop(r);
        assert!(f.entry.status().unwrap().handed_off);
        f.entry.scope.stop(p::Reason::UserCancelled, Instant::now());
        assert_eq!(f.entry.scope.first().unwrap(), None);
        assert!(f
            .owner
            .start_bound(start(), Instant::now(), None, Availability::Available, None)
            .is_err());
        assert!(f.input.current().is_err() && f.input.ready().begin_use().is_err());
    }
    #[test]
    fn delegated_prepare_rejects_desktop_only_key_recover_without_changing_context() {
        let owner = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
            "/unopened-apple-mode-test".into(),
        ));
        let context = Input::census_context(apple_wire::Mode::KeyRecover);
        assert!(context.valid());
        assert!(owner.apple_prepare_selection(&context).is_err());
        assert!(owner.inner.lock().prepared.is_none());
    }
}
