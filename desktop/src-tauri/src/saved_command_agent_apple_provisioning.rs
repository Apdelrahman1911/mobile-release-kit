//! Exact existing Apple Prepared link. No new native owner or material loan.
//! Approval retains Weak original inputs; history keeps only bounded DATA.
use super::super::*;
use super::{apple_wire, Intent};
use crate::{
    service_apple_provisioning_protocol as p, service_apple_provisioning_requests as requests,
    service_protocol as s,
};
use std::sync::{OnceLock, Weak};
fn refused() -> BridgeError {
    BridgeError::new("agent_apple_unavailable",
    "This original Apple preparation cannot be delegated. Check or stop the original; do not replay it.")
}
pub(in crate::saved_command_owner) fn mode(v: apple_wire::Mode) -> Result<p::Mode, BridgeError> {
    use apple_wire::Mode as A;
    Ok(match v {
        A::Review => p::Mode::Review,
        A::Register => p::Mode::Register,
        A::Reconcile => p::Mode::Reconcile,
        A::ProfileReview => p::Mode::ProfileReview,
        A::ProfileReuse => p::Mode::ProfileReuse,
        A::ProfileCreate => p::Mode::ProfileCreate,
        A::ProfileReconcile => p::Mode::ProfileReconcile,
        A::KeyReview => p::Mode::KeyReview,
        A::KeyPrepare => p::Mode::KeyPrepare,
        A::CertificateReview => p::Mode::CertificateReview,
        A::CertificateCreate => p::Mode::CertificateCreate,
        A::CertificateReconcile => p::Mode::CertificateReconcile,
        A::P12Review => p::Mode::P12Review,
        A::P12Reuse => p::Mode::P12Reuse,
        A::P12Save => p::Mode::P12Save,
        A::KeyRecover => return Err(refused()),
    })
}
pub(super) fn review(
    c: &Context,
    id: &str,
    generation: &str,
    revision: u32,
) -> Result<p::Review, BridgeError> {
    let Context::AppleProvisioning(c) = c else {
        return Err(refused());
    };
    if !c.valid() {
        return Err(refused());
    }
    let result = p::Review {
        mode: mode(c.mode)?,
        operation_id: s::Id::parse(id).map_err(|_| refused())?,
        owner_generation: s::Id::parse(generation).map_err(|_| refused())?,
        status_revision: revision,
        saved_config: p::Content {
            bytes: c.saved_config.bytes,
            sha256: c.saved_config.sha256.clone(),
        },
        saved_version: p::Version {
            bytes: c.saved_version.bytes,
            sha256: c.saved_version.sha256.clone(),
            name: c.saved_version.name.clone(),
            build: c.saved_version.build,
        },
    };
    if !result.valid() {
        return Err(refused());
    }
    Ok(result)
}
pub(crate) struct Approval {
    owner: Weak<Inner>,
    intent: Weak<Intent>,
    witness: Weak<()>,
    material: Weak<SelectedStoreMaterial>,
    project: String,
    registration: u32,
    root: RegisteredRoot,
    expires: Instant,
    review: p::Review,
}
impl Approval {
    pub(crate) fn preparation(&self)->Option<Arc<requests::preparation::Entry>>{self.intent.upgrade().and_then(|i|i.preparation.as_ref().map(|l|l.entry.clone()))}
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn project(&self) -> &str {
        &self.project
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn witness(&self) -> Weak<()> {
        self.witness.clone()
    }
    pub(crate) fn input(
        &self,
    ) -> Result<Arc<crate::asset_session::AppleProvisioningDocumentInput>, BridgeError> {
        self.intent
            .upgrade()
            .map(|i| i.input.clone())
            .ok_or_else(refused)
    }
    pub(crate) fn matches_root(&self, registration: u32, root: &RegisteredRoot) -> bool {
        self.registration == registration && self.root == *root
    }
    fn matches(&self, inner: &Arc<Inner>, prepared: &Prepared) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && prepared.registration == self.registration
            && prepared.project == self.root
            && prepared.expires == self.expires
            && prepared.projection.operation_id == self.review.operation_id.as_str()
            && prepared.projection.owner_generation == self.review.owner_generation.as_str()
            && prepared.apple.as_ref().is_some_and(|i| {
                self.intent.as_ptr() == Arc::as_ptr(i)
                    && self.witness.as_ptr() == Arc::as_ptr(&i.witness)
                    && prepared.projection.context
                        == Context::AppleProvisioning(i.input.context().clone())
            })
            && matches!(&prepared.material,Some(PrivateSigningMaterial::Store(m))
            if self.material.as_ptr()==Arc::as_ptr(m)
            &&PrivateSigningMaterial::Store(m.clone()).matches(&prepared.projection.context,self.registration,&self.root))
    }
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    scope: Arc<requests::NativeScope>,
    // Small identity DATA, not the Prepared/Session or a native resource Arc.
    _witness: Arc<()>,
    entry: OnceLock<Arc<requests::Entry>>,
    latest: Mutex<Option<requests::NativeData>>,
    consumed: AtomicBool,
}
impl Binding {
    pub(crate) fn scope(&self) -> &Arc<requests::NativeScope> {
        &self.scope
    }
    pub(in crate::saved_command_owner) fn read_end(&self) -> Instant {
        self.scope.read.end()
    }
    pub(crate) fn attach(&self, entry: &Arc<requests::Entry>) -> Result<(), BridgeError> {
        if !Arc::ptr_eq(&self.scope, entry.scope()) {
            return Err(refused());
        }
        // The native retirement callback and attachment share this DATA lock.
        // A callback before the relay cannot be lost or inferred from status.
        let latest = self.latest.lock().map_err(|_| refused())?;
        if self.entry.set(entry.clone()).is_err() {
            return Err(refused());
        }
        if let Some(n) = latest.as_ref() {
            entry.native(n.clone());
        }
        if self.scope.control.first().is_err() {
            entry.unknown(p::Reason::CleanupUnknown);
        }
        Ok(())
    }
    pub(crate) fn stop_at(&self, now: Instant) -> Option<(Reason, Instant)> {
        let _ = self
            .scope
            .current(self.consumed.load(Ordering::Acquire), now);
        match self.scope.control.first() {
            Ok(v) => v.map(|(r, t)| (native_reason(r), t)),
            Err(_) => {
                let original = self.entry.get().map_or_else(
                    || {
                        self.approval
                            .expires
                            .checked_sub(Duration::from_millis(p::INTENT_MS))
                            .unwrap_or(now)
                    },
                    |e| e.submitted_at(),
                );
                Some((
                    Reason::CleanupUnknown,
                    self.scope.control.uncertain_at(original.min(now)),
                ))
            }
        }
    }
    pub(crate) fn cancel(&self, reason: p::Reason, at: Instant) {
        self.scope.control.stop(reason, at);
    }
    fn unknown(&self) {
        self.scope.control.unknown(Instant::now());
        if let Some(e) = self.entry.get() {
            e.unknown(p::Reason::CleanupUnknown);
        }
    }
    fn publish(
        &self,
        p: &RunProjection,
        revision: u32,
        retired: bool,
        record: Option<p::RecordAtCompletion>,
    ) {
        if retired {
            self.scope.retired.store(true, Ordering::Release);
            self.scope.control.detach_returned();
        }
        let value = match projection(
            p,
            revision,
            retired,
            &self.scope.review,
            &self.scope.control,
            record,
        ) {
            Ok(v) => v,
            Err(_) => {
                self.unknown();
                return;
            }
        };
        let Ok(mut latest) = self.latest.lock() else {
            self.unknown();
            return;
        };
        if latest
            .as_ref()
            .is_some_and(|old| old.retired && *old != value)
        {
            drop(latest);
            self.unknown();
            return;
        }
        *latest = Some(value.clone());
        if let Some(e) = self.entry.get() {
            e.native(value);
        }
    }
}
/// Reuse the original watchdog's one control-select slot, not a relay task or
/// a new grant/clock owner. Read renewal/Drop changes the SAME retained facet
/// without a notification; keep sampling after STOP so an earlier original
/// revoke can still tighten F. The existing Unknown endpoint disables the slot.
pub(in crate::saved_command_owner) fn control_poll(owner: &Session) -> Option<Duration> {
    binding(owner).map(|_| Duration::from_millis(5))
}
pub(super) fn native_reason(r: p::Reason) -> Reason {
    match r {
        p::Reason::Expired => Reason::IntentExpired,
        p::Reason::ContextChanged => Reason::ContextChanged,
        p::Reason::Shutdown => Reason::Shutdown,
        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable => Reason::CleanupUnknown,
        p::Reason::TimedOut => Reason::TimedOut,
        _ => Reason::Cancelled,
    }
}
fn reason(r: Reason, control: &requests::Control) -> p::Reason {
    match r {
        Reason::None => p::Reason::None,
        Reason::Cancelled => control
            .first()
            .ok()
            .flatten()
            .map_or(p::Reason::UserCancelled, |(r, _)| r),
        Reason::ContextChanged
        | Reason::DocumentLost
        | Reason::StaleIntent
        | Reason::SavedSourceChanged
        | Reason::SavedSourceInvalid => p::Reason::ContextChanged,
        Reason::Shutdown => p::Reason::Shutdown,
        Reason::IntentExpired => p::Reason::Expired,
        Reason::TimedOut => p::Reason::TimedOut,
        Reason::CommandIncomplete => p::Reason::CommandIncomplete,
        Reason::RuntimeUnavailable | Reason::ResourcesUnavailable => p::Reason::Unavailable,
        Reason::CleanupUnknown => p::Reason::CleanupUnknown,
        Reason::CommandFailed => p::Reason::CommandFailed,
        _ => p::Reason::NativeRefused,
    }
}
fn report(t: &Terminal, r: &p::Review) -> Result<p::Report, BridgeError> {
    let Terminal::AppleProvisioning(t) = t else {
        return Err(refused());
    };
    if !t.settled() || mode(t.mode())? != r.mode {
        return Err(refused());
    }
    // Serialize only the original already-validated bounded public result.
    // No scope, certificate bytes, private output or history array is retained.
    let bytes = crate::edit_protocol::bounded(t.result.as_ref().ok_or_else(refused)?, 32 * 1024)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let comparison = if r.mode == p::Mode::ProfileReconcile {
        match v["reason"].as_str() {
            Some("same-response") => Some(p::Comparison::SameResponse),
            Some("unattributed") => Some(p::Comparison::Unattributed),
            Some("not-returned") => Some(p::Comparison::NotReturned),
            Some("inconclusive") => Some(p::Comparison::Inconclusive),
            _ => return Err(refused()),
        }
    } else {
        serde_json::from_value(
            v.get("comparison")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|_| refused())?
    };
    let attempt = if matches!(r.mode, p::Mode::Register | p::Mode::CertificateCreate)
        && !v["attempt"].is_null()
    {
        Some(p::Attempt {
            operation_id: s::Id::parse(v["attempt"]["operationId"].as_str().ok_or_else(refused)?)
                .map_err(|_| refused())?,
            status: v["attempt"]["status"].as_str().ok_or_else(refused)?.into(),
            cancellation_requested: v["attempt"]["cancellationRequested"]
                .as_bool()
                .ok_or_else(refused)?,
        })
    } else {
        None
    };
    let result = p::Report {
        decision: v["decision"].as_str().ok_or_else(refused)?.into(),
        comparison,
        attempt,
        certificate_id: v["certificateId"].as_str().map(str::to_owned),
        certificate_sha256: v["certificateSha256"].as_str().map(str::to_owned),
        do_not_replay: true,
        credential_ready: false,
    };
    if !result.valid_for(r) || crate::edit_protocol::bounded(&result, p::REPORT_LIMIT).is_err() {
        return Err(refused());
    }
    Ok(result)
}
fn projection(
    p: &RunProjection,
    revision: u32,
    retired: bool,
    review: &p::Review,
    control: &requests::Control,
    record_at_completion: Option<p::RecordAtCompletion>,
) -> Result<requests::NativeData, BridgeError> {
    if self::review(
        &p.context,
        &p.operation_id,
        &p.owner_generation,
        review.status_revision,
    )? != *review
        || p.phase == Phase::Unknown
    {
        return Err(refused());
    }
    let (state, outcome, result) = if retired {
        if p.phase != Phase::Terminal {
            return Err(refused());
        }
        let outcome = match p.outcome.ok_or_else(refused)? {
            Outcome::Complete => p::Outcome::Complete,
            Outcome::Refused => p::Outcome::Refused,
            Outcome::Cancelled => p::Outcome::Cancelled,
            Outcome::TimedOut => p::Outcome::TimedOut,
            Outcome::Failed => p::Outcome::Failed,
            Outcome::Unknown => return Err(refused()),
        };
        let state = match outcome {
            p::Outcome::Complete => s::OperationState::Succeeded,
            p::Outcome::Cancelled => s::OperationState::Cancelled,
            _ => s::OperationState::Failed,
        };
        let result = if outcome == p::Outcome::Complete {
            Some(report(p.result.as_ref().ok_or_else(refused)?, review)?)
        } else {
            None
        };
        (state, Some(outcome), result)
    } else {
        (
            match p.phase {
                Phase::AwaitingConsent => s::OperationState::Prepared,
                Phase::Stopping => s::OperationState::CancellationRequested,
                Phase::Starting | Phase::Running | Phase::Terminal => s::OperationState::Running,
                _ => return Err(refused()),
            },
            None,
            None,
        )
    };
    Ok(requests::NativeData {
        operation: p::Operation {
            operation_id: review.operation_id.clone(),
            owner_generation: review.owner_generation.clone(),
            status_revision: revision,
        },
        state,
        reason: reason(p.reason, control),
        outcome,
        result,
        retired,
        record_at_completion,
    })
}
pub(in crate::saved_command_owner) fn prepared_binding(p: &Prepared) -> Option<&Arc<Binding>> {
    p.apple.as_ref().and_then(|i| i.agent.get())
}
pub(in crate::saved_command_owner) fn binding(owner: &Session) -> Option<&Arc<Binding>> {
    owner.apple.intent.as_ref().and_then(|i| i.agent.get())
}
pub(in crate::saved_command_owner) fn start_matches(
    p: &Prepared,
    entry: Option<&Arc<requests::Entry>>,
) -> bool {
    if !super::preparation::start_matches(p,entry){return false;}
    match (prepared_binding(p), entry) {
        (None, None) => true,
        (Some(b), Some(e)) => {
            b.entry.get().is_some_and(|held| Arc::ptr_eq(held, e))
                && Arc::ptr_eq(&b.scope, e.scope())
                && !b.consumed.load(Ordering::Acquire)
                && p.apple.as_ref().is_some_and(|i| {
                    Arc::ptr_eq(&i.witness, &b._witness)
                        && b.approval.intent.as_ptr() == Arc::as_ptr(i)
                })
        }
        _ => false,
    }
}
pub(in crate::saved_command_owner) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    if prepared_binding(p).is_some_and(|b| b.consumed.swap(true, Ordering::AcqRel)) {
        Err(refused())
    } else {
        Ok(())
    }
}
pub(in crate::saved_command_owner) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if let Some(b) = binding(&a.owner) {
            b.publish(&a.projection, r.revision, false, None)
        }
    } else if let Some(p) = &r.prepared {
        if let Some(b) = prepared_binding(p) {
            b.publish(&p.projection, r.revision, false, None)
        }
    }
}
pub(in crate::saved_command_owner) fn retired_prepared(
    p: &Prepared,
    reason: Reason,
    revision: u32,
) {
    super::preparation::retired(p);
    if let Some(b) = prepared_binding(p) {
        b.publish(&retire(p.projection.clone(), reason), revision, true, None)
    }
}
pub(in crate::saved_command_owner) fn retired(
    a: &Active,
    revision: u32,
    registry: &super::Registry,
) {
    let Some(b) = binding(&a.owner) else { return };
    let record = (|| -> Result<Option<p::RecordAtCompletion>, BridgeError> {
        let mut view = a.projection.clone().apple()?;
        // SAME native saved-publication rules, after actual private retirement.
        // No recovery projection or later vault inventory reconstruction.
        super::profile_review::project(registry, &mut view);
        super::key_review::project(registry, &mut view);
        super::p12_review::project(registry, &mut view);
        let selected = match b.scope.review.mode.record_kind() {
            Some(p::RecordKind::AppleProfile) => view.saved_profile,
            Some(p::RecordKind::AppleDistributionKey) => view.saved_key,
            Some(p::RecordKind::AppleP12) => view.saved_p12,
            None => None,
        };
        selected
            .map(|r| {
                let reference = s::CredentialReference {
                    vault_id: s::Id::parse(&r.vault_id).map_err(|_| refused())?,
                    generation_id: s::Id::parse(&r.generation_id).map_err(|_| refused())?,
                    record_id: s::Id::parse(&r.record_id).map_err(|_| refused())?,
                    revision_id: s::Id::parse(&r.revision_id).map_err(|_| refused())?,
                    revision_counter: r.revision_counter,
                };
                let record = p::RecordAtCompletion {
                    kind: b.scope.review.mode.record_kind().ok_or_else(refused)?,
                    reference,
                };
                if !record.valid_for(&b.scope.review) {
                    return Err(refused());
                }
                Ok(record)
            })
            .transpose()
    })();
    match record {
        Ok(record) => b.publish(&a.projection, revision, true, record),
        Err(_) => b.unknown(),
    }
}
impl SavedCommandOwner {
    pub(crate) fn apple_approval(
        &self,
        mode: p::Mode,
        operation: &s::Id,
        generation: &s::Id,
        revision: u32,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if self.inner.poisoned.load(Ordering::SeqCst) || r.disabled || r.document_lost || r.stopping
        {
            return Err(refused());
        }
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| {
                prepared_binding(p).is_none()
                    && p.projection.phase == Phase::AwaitingConsent
                    && p.projection.intent_usable && super::preparation::current_ready(p)
                    && r.revision == revision
                    && p.projection.operation_id == operation.as_str()
                    && p.projection.owner_generation == generation.as_str()
            })
            .ok_or_else(refused)?;
        let review = review(
            &prepared.projection.context,
            operation.as_str(),
            generation.as_str(),
            revision,
        )?;
        if review.mode != mode {
            return Err(refused());
        }
        let intent = prepared.apple.as_ref().ok_or_else(refused)?;
        let material = match &prepared.material {
            Some(PrivateSigningMaterial::Store(m)) => m,
            _ => return Err(refused()),
        };
        if !Arc::ptr_eq(material, intent.input.material()) {
            return Err(refused());
        }
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            intent: Arc::downgrade(intent),
            witness: Arc::downgrade(&intent.witness),
            material: Arc::downgrade(material),
            project: intent.input.context().project_id.clone(),
            registration: prepared.registration,
            root: prepared.project.clone(),
            expires: prepared.expires,
            review,
        }))
    }
    pub(crate) fn bind_apple_approval(
        &self,
        approval: Arc<Approval>,
        scope: Arc<requests::NativeScope>,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if r.revision != approval.review.status_revision
            || scope.review != approval.review
            || scope.witness.as_ptr() != approval.witness.as_ptr()
            || scope.review_id != approval.review.operation_id
            || scope.expires != approval.expires.min(scope.read.end())
            || scope.current(false, Instant::now()).is_err()
        {
            return Err(refused());
        }
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| prepared_binding(p).is_none() && approval.matches(&self.inner, p))
            .ok_or_else(refused)?;
        let intent = prepared.apple.as_ref().ok_or_else(refused)?;
        let link = Arc::new(Binding {
            _witness: intent.witness.clone(),
            approval,
            scope,
            entry: OnceLock::new(),
            latest: Mutex::new(None),
            consumed: AtomicBool::new(false),
        });
        if let Some(preparation)=&intent.preparation{preparation.entry.claim_start().map_err(|_|refused())?;}
        if intent.agent.set(link.clone()).is_err() {
            if let Some(preparation)=&intent.preparation{preparation.entry.unknown(p::Reason::CleanupUnknown);}
            link.scope.control.unknown(Instant::now());
            return Err(refused());
        }
        changed(&r);
        Ok(link)
    }
    pub(crate) fn apple_approval_current(&self, approval: &Approval) -> bool {
        let r = self.inner.lock();
        !r.disabled
            && !r.stopping
            && !r.document_lost
            && !self.inner.poisoned.load(Ordering::SeqCst)
            && r.prepared
                .as_ref()
                .is_some_and(|p| approval.matches(&self.inner, p))
    }
    pub(crate) fn stop_agent_apple(&self, link: &Binding, reason: p::Reason, at: Instant) {
        link.cancel(reason, at);
        let mut r = self.inner.lock();
        if r.prepared
            .as_ref()
            .and_then(prepared_binding)
            .is_some_and(|b| std::ptr::eq(b.as_ref(), link))
        {
            self.inner.retire_prepared(&mut r, native_reason(reason));
        } else if let Some(owner) = r
            .active
            .as_ref()
            .filter(|a| binding(&a.owner).is_some_and(|b| std::ptr::eq(b.as_ref(), link)))
            .map(|a| a.owner.clone())
        {
            self.inner
                .stop_locked(&mut r, &owner, native_reason(reason), at);
        } else if !link.scope.retired.load(Ordering::Acquire) {
            link.unknown()
        }
    }
}
#[cfg(test)]
#[path = "saved_command_agent_apple_provisioning_tests.rs"]
mod tests;
