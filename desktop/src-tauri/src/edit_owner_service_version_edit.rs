//! One permission on an already genuine ReleaseVersion Prepared. All child,
//! source, publication and finality work stays in this original EditOwner.
use super::*;
use crate::{
    application_service_host::NativeProject, service_protocol::Id,
    service_version_edit_protocol as p, service_version_edit_requests as requests,
};

pub(crate) struct Link {
    pub lease: Arc<requests::Lease>,
    pub project: NativeProject,
    service: std::sync::Weak<crate::application_service::ApplicationService>,
}
pub(crate) struct PreparedOriginal {
    session: Arc<Session>,
    pub review: p::Review,
    pub end: Instant,
}
pub(crate) struct Claim {
    session: Arc<Session>,
    entry: Option<Arc<requests::Entry>>,
}
pub(crate) enum Decision {
    Observe,
    Apply(Claim),
}

fn id(v: &str) -> Result<Id, BridgeError> {
    Id::parse(v).map_err(|_| invalid_owner())
}
fn review(a: &ActiveOwner, revision: u32) -> Result<p::Review, BridgeError> {
    if a.session.domain != EditDomain::ReleaseVersion
        || a.session.saved_text_recovery
        || a.projection.phase != Phase::Reviewing
        || a.projection.native_reason != Reason::None
        || a.projection.native_finality != NativeFinality::Pending
        || a.projection.apply_submitted
        || a.cleanup_start.is_some()
        || a.unknown
        || !a.opened
        || !a.prepared
        || a.claimed_seq != 1
        || *a.session.stop.borrow()
        || Instant::now() >= a.review_end
    {
        return Err(invalid_owner());
    }
    let detail = a
        .projection
        .release_version
        .as_ref()
        .ok_or_else(invalid_owner)?;
    let checkout = detail.checkout.as_ref().ok_or_else(invalid_owner)?;
    let prepared = detail.prepared.as_ref().ok_or_else(invalid_owner)?;
    if detail.recovery.is_some()
        || prepared.view.intent != version_wire::Intent::Edit
        || !prepared.view.matches_checkout(checkout)
        || !detail
            .submission
            .as_ref()
            .is_some_and(|s| s.matches(checkout, &prepared.view))
    {
        return Err(invalid_owner());
    }
    let version_wire::Before::Present { bytes, sha256, .. } = &prepared.view.file.before else {
        return Err(invalid_owner());
    };
    let result = p::Review {
        original: p::Original {
            session_id: id(&a.session.id)?,
            owner_generation: id(&a.projection.owner_generation)?,
            revision: id(&checkout.revision)?,
            plan_token: id(&prepared.plan_token)?,
        },
        native_status_revision: revision,
        name: prepared.view.values.name.clone(),
        build: prepared.view.values.build.clone(),
        source: prepared.view.source.clone(),
        before_bytes: *bytes,
        before_sha256: sha256.clone(),
        after_bytes: prepared.view.file.after.bytes,
        after_sha256: prepared.view.file.after.sha256.clone(),
        candidate_id: a
            .session
            .reserved_version
            .as_ref()
            .map(|h| h.candidate_data().to_owned()),
    };
    result.validate().map_err(|_| invalid_owner())?;
    Ok(result)
}
fn window(r: &Registry, window: &str) -> Result<(), BridgeError> {
    if r.window.as_deref() != Some(window)
        || !r.document_bound
        || r.document_lost
        || r.disabled
        || r.exhausted
        || r.stopping
    {
        Err(invalid_owner())
    } else {
        Ok(())
    }
}
impl EditOwner {
    pub(crate) fn version_edit_has_lease(&self, session: &str) -> bool {
        self.inner.lock().active.as_ref().is_some_and(|a| {
            a.session.id == session && a.session.agent_version_edit.get().is_some()
        })
    }
    pub(crate) fn version_edit_prepared(
        &self,
        window_name: &str,
        expected: &p::Original,
        status_revision: u32,
    ) -> Result<PreparedOriginal, BridgeError> {
        let r = self.inner.lock();
        window(&r, window_name)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let review = review(a, r.revision)?;
        if review.original != *expected
            || r.revision != status_revision
            || a.session.agent_version_edit.get().is_some()
        {
            return Err(invalid_owner());
        }
        Ok(PreparedOriginal {
            session: a.session.clone(),
            review,
            end: reserved_review_end(&a.session, a.review_end),
        })
    }
    pub(crate) fn version_edit_install(
        &self,
        window_name: &str,
        original: PreparedOriginal,
        project: NativeProject,
        scope: requests::Scope,
        nonce: Id,
        service: &Arc<crate::application_service::ApplicationService>,
    ) -> Result<(), BridgeError> {
        let end = original
            .end
            .min(scope.read.end())
            .min(Instant::now() + REVIEW);
        let lease = requests::Lease::new(
            Id::random().map_err(public)?,
            nonce,
            scope,
            original.review.clone(),
            end,
            Arc::downgrade(&original.session.wake),
        )
        .map_err(public)?;
        service
            .version_edit_requests()
            .install(lease.clone(), || {
                let r = self.inner.lock();
                window(&r, window_name).map_err(|_| crate::service_protocol::Error::Conflict)?;
                let a = r
                    .active
                    .as_ref()
                    .filter(|a| Arc::ptr_eq(&a.session, &original.session))
                    .ok_or(crate::service_protocol::Error::Conflict)?;
                if review(a, r.revision).map_err(|_| crate::service_protocol::Error::Conflict)?
                    != original.review
                    || a.projection.project_id != project.runtime_id
                {
                    return Err(crate::service_protocol::Error::Conflict);
                }
                a.session
                    .agent_version_edit
                    .set(Arc::new(Link {
                        lease: lease.clone(),
                        project,
                        service: Arc::downgrade(service),
                    }))
                    .map_err(|_| crate::service_protocol::Error::Conflict)
            })
            .map_err(public)?;
        original.session.wake.notify_waiters();
        Ok(())
    }
    pub(crate) fn version_edit_link(
        &self,
        window_name: &str,
        session: &str,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        window(&r, window_name)?;
        r.active
            .as_ref()
            .filter(|a| a.session.domain == EditDomain::ReleaseVersion && a.session.id == session)
            .and_then(|a| a.session.agent_version_edit.get())
            .cloned()
            .ok_or_else(invalid_owner)
    }
    /// No publisher, status bump or retirement occurs on a losing request.
    pub(crate) fn version_edit_preclaim(
        &self,
        window_name: &str,
        session: &str,
        plan: &str,
        entry: Option<&Arc<requests::Entry>>,
    ) -> Result<Decision, BridgeError> {
        let r = self.inner.lock();
        window(&r, window_name)?;
        let a = r
            .active
            .as_ref()
            .filter(|a| a.session.id == session)
            .ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_version_edit
            .get()
            .ok_or_else(invalid_owner)?;
        if link.lease.review.original.plan_token.as_str() != plan {
            return Err(invalid_owner());
        }
        if let Some(e) = entry {
            if !Arc::ptr_eq(&e.lease, &link.lease)
                || !link
                    .lease
                    .entry()
                    .map_err(public)?
                    .is_some_and(|v| Arc::ptr_eq(&v, e))
            {
                return Err(invalid_owner());
            }
            // Repeated originals observe before native currentness/publisher paths.
            if !e.pending().map_err(public)? {
                return Ok(Decision::Observe);
            }
        }
        if review(a, r.revision)? != link.lease.review {
            return Err(invalid_owner());
        }
        if let Some(e) = entry {
            if !e.preclaim().map_err(public)? {
                return Ok(Decision::Observe);
            }
        } else {
            link.lease.gui_claim().map_err(public)?;
        }
        Ok(Decision::Apply(Claim {
            session: a.session.clone(),
            entry: entry.cloned(),
        }))
    }
    pub(crate) fn apply_version_edit_claimed(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        session: &str,
        plan: &str,
        root: RegisteredEditRoot,
        claim: &Claim,
    ) -> Result<ReleaseVersionEditStatus, BridgeError> {
        self.apply_domain_configuration(
            Some(publisher),
            window,
            EditDomain::ReleaseVersion,
            session,
            plan,
            Some(root),
            false,
            None,
            None,
            Some(claim),
        )?
        .release_version()
    }
    pub(crate) fn version_edit_claim_failed(&self, claim: &Claim) {
        if let Some(e) = &claim.entry {
            let _ = e.cancel(Instant::now());
        }
        self.inner
            .trigger(&claim.session.id, Reason::CallerLost, Instant::now());
    }
    pub(crate) fn version_edit_relay_lost(&self) {
        let r = self.inner.lock();
        if let Some(l) = r
            .active
            .as_ref()
            .and_then(|a| a.session.agent_version_edit.get())
        {
            let _ = l.lease.revoke(Instant::now());
        }
    }
}
fn public(e: crate::service_protocol::Error) -> BridgeError {
    crate::asset_session::application_service::public_error(e)
}
pub(super) fn consume(a: &ActiveOwner, claim: Option<&Claim>) -> bool {
    let Some(link) = a.session.agent_version_edit.get() else {
        return claim.is_none();
    };
    let Some(claim) = claim.filter(|c| Arc::ptr_eq(&c.session, &a.session)) else {
        return false;
    };
    match (&claim.entry, link.lease.entry()) {
        (Some(e), Ok(Some(current))) if Arc::ptr_eq(e, &current) => e.enqueue().is_ok(),
        (None, Ok(None)) => true, // The private GUI preclaim spent the unused lease.
        _ => false,
    }
}
pub(super) fn cancellation_at(session: &Session, now: Instant) -> Option<(Instant, Reason)> {
    let link = session.agent_version_edit.get()?;
    // A spent/withdrawn unused lease never borrows its Service/READ failures
    // into a GUI winner. A claimed original does retain that same Service.
    if let Ok(Some(entry)) = link.lease.entry() {
        if link
            .service
            .upgrade()
            .is_none_or(|s| s.native_history_current().is_err())
        {
            entry.unknown();
            session.resource_unknown.store(true, Ordering::SeqCst);
            return Some((now, Reason::CleanupUnknown));
        }
    }
    match link.lease.stop_at(now) {
        Ok(at) => at.map(|at| (at, Reason::Cancelled)),
        Err(_) => {
            session.resource_unknown.store(true, Ordering::SeqCst);
            if let Ok(Some(e)) = link.lease.entry() {
                e.unknown();
            }
            Some((now, Reason::CleanupUnknown))
        }
    }
}
pub(super) fn unknown(session: &Session) {
    if let Some(link) = session.agent_version_edit.get() {
        if let Ok(Some(e)) = link.lease.seal() {
            e.unknown();
        }
    }
}
pub(super) fn retired(r: &Registry, session: &Session, unknown: bool) {
    let Some(link) = session.agent_version_edit.get() else {
        return;
    };
    let Ok(Some(e)) = link.lease.seal() else {
        return;
    };
    let service_current = link
        .service
        .upgrade()
        .is_some_and(|s| s.native_history_current().is_ok());
    let result = r
        .last
        .as_ref()
        .filter(|p| {
            !unknown
                && service_current
                && p.session_id == session.id
                && p.domain == EditDomain::ReleaseVersion
                && p.native_finality == NativeFinality::Settled
                && !p.late_settled
        })
        .and_then(|p| {
            let (effect, journal) = match p.core_outcome.as_ref() {
                Some(c) if c.resources == ResourceState::Settled => (
                    match c.effect {
                        Effect::NotStarted => p::Effect::NotStarted,
                        Effect::Unchanged => p::Effect::Unchanged,
                        Effect::RolledBack => p::Effect::RolledBack,
                        Effect::Committed => p::Effect::Committed,
                        Effect::Unknown => return None,
                    },
                    match c.journal {
                        Journal::NotCreated => p::Journal::NotCreated,
                        Journal::Clean => p::Journal::Clean,
                        Journal::RecoveryRequired => p::Journal::RecoveryRequired,
                        Journal::Unknown => return None,
                    },
                ),
                None if !p.apply_submitted => (p::Effect::NotStarted, p::Journal::NotCreated),
                _ => return None,
            };
            Some(p::Final {
                effect,
                journal,
                cancelled: matches!(
                    p.native_reason,
                    Reason::Cancelled
                        | Reason::Discarded
                        | Reason::CallerLost
                        | Reason::ReviewExpired
                ),
                apply_submitted: p.apply_submitted,
            })
        });
    if e.retired(result).is_err() {
        e.unknown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn data() -> EditProjection {
        EditProjection {
            domain: EditDomain::ReleaseVersion,
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            identity: None,
            project_id: "p".into(),
            session_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            phase: Phase::Unknown,
            review_remaining_ms: 0,
            checkout: None,
            prepared: None,
            recovery: None,
            apply_submitted: false,
            core_outcome: None,
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    fn view() -> version_wire::PreparedView {
        let before = "VERSION_NAME=1.2\nBUILD_NUMBER=7\n";
        let after = "VERSION_NAME=1.2\nBUILD_NUMBER=8\n";
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"source":"version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER","iosEnabled":true,"intent":"edit","values":{"name":"1.2","build":"8"},
            "file":{"path":"version.properties","action":"replace","before":{"state":"present","text":before,"bytes":before.len(),"sha256":format!("{:x}",Sha256::digest(before.as_bytes()))},
                "after":{"text":after,"bytes":after.len(),"sha256":format!("{:x}",Sha256::digest(after.as_bytes()))},"requestedMode":420,"preserveMode":true},"createDirectories":[],
            "lineEndings":{"before":["lf"],"after":["lf"],"finalNewlineBefore":true,"finalNewlineAfter":true,"preserved":true},"validation":{"valid":true,"state":"format-valid","issues":[]}})).unwrap()
    }
    fn owner() -> EditOwner {
        EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/never-opened-version-original",
        )))
    }
    #[test]
    fn real_owner_without_original_prepared_cannot_mint_or_claim_lease() {
        let owner = owner();
        owner.initial_document("main").unwrap();
        let original = p::Original {
            session_id: id(&"a".repeat(32)).unwrap(),
            owner_generation: id(&"b".repeat(32)).unwrap(),
            revision: id(&"c".repeat(32)).unwrap(),
            plan_token: id(&"d".repeat(32)).unwrap(),
        };
        assert!(owner.version_edit_prepared("main", &original, 0).is_err());
        assert!(owner
            .version_edit_preclaim(
                "main",
                original.session_id.as_str(),
                original.plan_token.as_str(),
                None
            )
            .is_err());
        assert!(!owner.version_edit_has_lease(original.session_id.as_str()));
        assert!(owner.inner.lock().active.is_none());
        // Even a retained well-shaped comparison is not an actual Prepared.
        let mut data = data();
        data.release_version = Some(version_wire::Details {
            prepared: Some(version_wire::Prepared {
                revision: original.revision.as_str().into(),
                plan_token: original.plan_token.as_str().into(),
                draft_revision: 1,
                baseline_generation: 1,
                view: view(),
            }),
            ..Default::default()
        });
        owner.inner.lock().last = Some(data);
        assert!(owner.version_edit_prepared("main", &original, 0).is_err());
        assert!(owner.inner.lock().active.is_none());
    }
    #[test]
    fn borrowed_original_version_and_foreign_last_capacities_are_never_free_credit() {
        let owner = owner();
        let initial = owner.version_agent_edit_backing().unwrap();
        let mut data = data();
        let mut view = view();
        view.file.after.text.reserve_exact(1024 * 1024);
        let capacity = view.file.after.text.capacity();
        let ptr = view.file.after.text.as_ptr();
        data.release_version = Some(version_wire::Details {
            prepared: Some(version_wire::Prepared {
                revision: "c".repeat(32),
                plan_token: "d".repeat(32),
                draft_revision: 1,
                baseline_generation: 1,
                view,
            }),
            ..Default::default()
        });
        owner.inner.lock().last = Some(data);
        assert!(owner.version_agent_edit_backing().unwrap() >= initial + 3 * capacity);
        assert_eq!(
            owner
                .inner
                .lock()
                .last
                .as_ref()
                .unwrap()
                .release_version
                .as_ref()
                .unwrap()
                .prepared
                .as_ref()
                .unwrap()
                .view
                .file
                .after
                .text
                .as_ptr(),
            ptr
        );
        let mut foreign = super::tests::data();
        foreign.domain = EditDomain::Configuration;
        foreign.checkout = Some(wire::Checkout {
            revision: "e".repeat(32),
            base: Value::String(String::with_capacity(2 * 1024 * 1024)),
        });
        owner.inner.lock().last = Some(foreign);
        assert!(owner.version_agent_edit_backing().unwrap() >= initial + 2 * 1024 * 1024);
        owner
            .inner
            .lock()
            .last
            .as_mut()
            .unwrap()
            .checkout
            .as_mut()
            .unwrap()
            .base = Value::String(String::with_capacity(64 * 1024 * 1024));
        assert!(owner.version_agent_edit_backing().is_err());
        assert!(owner.inner.lock().last.is_some());
    }
}
