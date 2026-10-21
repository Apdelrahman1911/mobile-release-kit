//! One consent link INSIDE the existing SavedCommandOwner. No new process,
//! credential loan, clock, journal or finality owner. Retained history is DATA.
use super::*;
use crate::{
    service_protocol as s, service_store_protocol as p, service_store_requests as requests,
};
use std::sync::{OnceLock, Weak};

fn refused() -> BridgeError {
    BridgeError::new("agent_store_unavailable","This original Store review cannot be delegated. Check or stop the original request; do not replay it.")
}
fn version(v: &android_wire::SavedVersion) -> p::Version {
    p::Version {
        bytes: v.bytes,
        sha256: v.sha256.clone(),
        name: v.name.clone(),
        build: v.build,
    }
}
fn review(
    c: &Context,
    id: &str,
    generation: &str,
    revision: u32,
) -> Result<p::Review, BridgeError> {
    let (kind, platform, config, saved_version, candidate) = match c {
        Context::LocalStorePreflight(c) if c.query.is_none() && c.ios_record.is_none() => {
            let platform = match c.platform {
                store_wire::AccessPlatform::Android => p::Platform::Android,
                store_wire::AccessPlatform::Ios => p::Platform::Ios,
                _ => return Err(refused()),
            };
            (
                p::Kind::AccessCheck,
                platform,
                p::Content {
                    bytes: c.saved_config.bytes,
                    sha256: c.saved_config.sha256.clone(),
                },
                version(&c.saved_version),
                None,
            )
        }
        Context::LocalStorePrepare(c) if c.later.is_none() => (
            p::Kind::CandidatePrepare,
            if c.platform == prepare_wire::Platform::Android {
                p::Platform::Android
            } else {
                p::Platform::Ios
            },
            p::Content {
                bytes: c.saved_config.bytes,
                sha256: c.saved_config.sha256.clone(),
            },
            version(&c.saved_version),
            Some(p::Candidate {
                operation_id: c.candidate_operation_id.clone(),
                sha256: c.candidate_sha256.clone(),
            }),
        ),
        _ => return Err(refused()),
    };
    let r = p::Review {
        kind,
        platform,
        saved_config: config,
        saved_version,
        candidate,
        operation_id: s::Id::parse(id).map_err(|_| refused())?,
        owner_generation: s::Id::parse(generation).map_err(|_| refused())?,
        status_revision: revision,
    };
    if !r.valid() {
        return Err(refused());
    }
    Ok(r)
}
pub(super) fn witness(context: &Context) -> Option<Arc<()>> {
    match context {
        Context::LocalStorePreflight(c)
            if c.query.is_none()
                && c.ios_record.is_none()
                && c.platform != store_wire::AccessPlatform::Both =>
        {
            Some(Arc::new(()))
        }
        Context::LocalStorePrepare(c) if c.later.is_none() => Some(Arc::new(())),
        _ => None,
    }
}
/// Weak comparison only. This cannot keep runtime/material/source custody
/// alive after the actual Saved owner retires.
pub(crate) struct Approval {
    owner: Weak<Inner>,
    witness: Weak<()>,
    material: Weak<SelectedStoreMaterial>,
    context: Context,
    registration: u32,
    root: RegisteredRoot,
    expires: Instant,
    review: p::Review,
}
impl Approval {
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn project(&self) -> &str {
        self.context.project_id()
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn witness(&self) -> Weak<()> {
        self.witness.clone()
    }
    pub(crate) fn matches_root(&self, registration: u32, root: &RegisteredRoot) -> bool {
        self.registration == registration && self.root == *root
    }
    fn matches(&self, inner: &Arc<Inner>, prepared: &Prepared) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && prepared.registration == self.registration
            && prepared.project == self.root
            && prepared.projection.context == self.context
            && prepared.expires == self.expires
            && prepared.projection.operation_id == self.review.operation_id.as_str()
            && prepared.projection.owner_generation == self.review.owner_generation.as_str()
            && prepared
                .store_witness
                .as_ref()
                .is_some_and(|w| self.witness.as_ptr() == Arc::as_ptr(w))
            && matches!(&prepared.material,Some(PrivateSigningMaterial::Store(m)) if self.material.as_ptr()==Arc::as_ptr(m)
                &&PrivateSigningMaterial::Store(m.clone()).matches(&self.context,self.registration,&self.root))
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
    pub(super) fn read_end(&self) -> Instant {
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
    fn publish(&self, p: &RunProjection, revision: u32, retired: bool) {
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
pub(super) fn control_poll(owner: &Session) -> Option<Duration> {
    owner.agent_store.as_ref().map(|_| Duration::from_millis(5))
}
fn native_reason(r: p::Reason) -> Reason {
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
fn report(t: &Terminal, review: &p::Review) -> Result<p::Report, BridgeError> {
    // The original decoder already validated full context, fixed scope and
    // lifetime. Project only bounded nonsecret fields after native retirement.
    let (value, kind) = match t {
        Terminal::LocalStorePreflight(t) => (
            crate::edit_protocol::bounded(
                t.result.as_ref().ok_or_else(refused)?,
                store_wire::RESPONSE_LIMIT,
            )?,
            p::Kind::AccessCheck,
        ),
        Terminal::LocalStorePrepare(t) => (
            crate::edit_protocol::bounded(
                t.result.as_ref().ok_or_else(refused)?,
                prepare_wire::RESPONSE_LIMIT,
            )?,
            p::Kind::CandidatePrepare,
        ),
        _ => return Err(refused()),
    };
    if kind != review.kind {
        return Err(refused());
    }
    let v: serde_json::Value = serde_json::from_slice(&value).map_err(|_| refused())?;
    let projected = match kind {
        p::Kind::AccessCheck => {
            serde_json::json!({"kind":"access-check","findings":v["findings"],"limitations":v["limitations"]})
        }
        p::Kind::CandidatePrepare => {
            let i = &v["preparedIntent"];
            serde_json::json!({"kind":"candidate-prepare","headSequence":v["headSequence"],
            "operationId":i["operationId"],"candidateSha256":i["candidateSha256"],"intentSha256":i["intentSha256"],
            "storePreconditionSha256":i["storePreconditionSha256"],"limitations":i["limitations"]})
        }
    };
    let bytes = crate::edit_protocol::bounded(&projected, p::STATUS_LIMIT)?;
    let result: p::Report = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if !result.valid_for(review) {
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
    })
}
pub(super) fn start_matches(p: &Prepared, entry: Option<&Arc<requests::Entry>>) -> bool {
    match (&p.agent_store, entry) {
        (None, None) => true,
        (Some(link), Some(entry)) => {
            link.entry.get().is_some_and(|e| Arc::ptr_eq(e, entry))
                && Arc::ptr_eq(link.scope(), entry.scope())
                && !link.consumed.load(Ordering::Acquire)
                && p.projection.context == link.approval.context
                && p.store_witness
                    .as_ref()
                    .is_some_and(|w| Arc::ptr_eq(w, &link._witness))
        }
        _ => false,
    }
}
pub(super) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    if let Some(link) = &p.agent_store {
        if link.consumed.swap(true, Ordering::AcqRel) {
            return Err(refused());
        }
    }
    Ok(())
}
pub(super) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if let Some(b) = &a.owner.agent_store {
            b.publish(&a.projection, r.revision, false);
        }
    } else if let Some(p) = &r.prepared {
        if let Some(b) = &p.agent_store {
            b.publish(&p.projection, r.revision, false);
        }
    }
}
pub(super) fn retired_prepared(p: &Prepared, reason: Reason, revision: u32) {
    if let Some(b) = &p.agent_store {
        b.publish(&retire(p.projection.clone(), reason), revision, true);
    }
}
pub(super) fn retired(a: &Active, revision: u32) {
    if let Some(b) = &a.owner.agent_store {
        b.publish(&a.projection, revision, true);
    }
}
impl SavedCommandOwner {
    pub(crate) fn store_approval(
        &self,
        kind: p::Kind,
        operation: &s::Id,
        generation: &s::Id,
        revision: u32,
    ) -> Result<Arc<Approval>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| {
                p.agent_store.is_none()
                    && p.projection.phase == Phase::AwaitingConsent
                    && p.projection.intent_usable
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
        if review.kind != kind
            || self.inner.poisoned.load(Ordering::SeqCst)
            || r.disabled
            || r.document_lost
            || r.stopping
        {
            return Err(refused());
        }
        let material = match &prepared.material {
            Some(PrivateSigningMaterial::Store(m)) => m,
            _ => return Err(refused()),
        };
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            witness: Arc::downgrade(prepared.store_witness.as_ref().ok_or_else(refused)?),
            material: Arc::downgrade(material),
            context: prepared.projection.context.clone(),
            registration: prepared.registration,
            root: prepared.project.clone(),
            expires: prepared.expires,
            review,
        }))
    }
    pub(crate) fn bind_store_approval(
        &self,
        approval: Arc<Approval>,
        scope: Arc<requests::NativeScope>,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if r.revision != approval.review.status_revision
            || scope.review != approval.review
            || scope.witness.as_ptr() != approval.witness.as_ptr()
            || scope.expires != approval.expires
            || scope.current(false, Instant::now()).is_err()
        {
            return Err(refused());
        }
        let prepared = r
            .prepared
            .as_mut()
            .filter(|p| p.agent_store.is_none() && approval.matches(&self.inner, p))
            .ok_or_else(refused)?;
        let link = Arc::new(Binding {
            _witness: prepared.store_witness.as_ref().ok_or_else(refused)?.clone(),
            approval,
            scope,
            entry: OnceLock::new(),
            latest: Mutex::new(None),
            consumed: AtomicBool::new(false),
        });
        prepared.agent_store = Some(link.clone());
        // No status revision fabrication. Binding is the actual same Prepared;
        // the public permission endpoint carries its separate comparison DATA.
        changed(&r);
        Ok(link)
    }
    pub(crate) fn store_approval_current(&self, approval: &Approval) -> bool {
        let r = self.inner.lock();
        !r.disabled
            && !r.stopping
            && !r.document_lost
            && !self.inner.poisoned.load(Ordering::SeqCst)
            && r.prepared
                .as_ref()
                .is_some_and(|p| approval.matches(&self.inner, p))
    }
    pub(crate) fn start_agent_store(
        &self,
        entry: &Arc<requests::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: store_wire::Availability,
        material: Arc<SelectedStoreMaterial>,
    ) -> Result<AgentStoreAdmitted, BridgeError> {
        let input = Start {
            operation_id: entry.scope().review.operation_id.as_str().into(),
            owner_generation: entry.scope().review.owner_generation.as_str().into(),
        };
        let r = self.inner.lock();
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| start_matches(p, Some(entry)))
            .ok_or_else(refused)?;
        if !matches!(&prepared.material,Some(PrivateSigningMaterial::Store(original)) if Arc::ptr_eq(original,&material))
        {
            return Err(refused());
        }
        match &prepared.projection.context {
            Context::LocalStorePreflight(c)
                if c.query.is_none()
                    && c.ios_record.is_none()
                    && c.platform != store_wire::AccessPlatform::Both =>
            {
                let v = serde_json::json!({"operationId":input.operation_id,"ownerGeneration":input.owner_generation,"consentVersion":c.platform.consent()});
                let consent = store_wire::start(&v)?;
                if !material.accepts_access_consent(&consent) {
                    return Err(refused());
                }
            }
            Context::LocalStorePrepare(c) if c.later.is_none() => {
                let v = serde_json::json!({"operationId":input.operation_id,"ownerGeneration":input.owner_generation,"consentVersion":c.consent()});
                let consent = prepare_wire::start(&v)?;
                if !material.accepts_prepare_consent(&consent) {
                    return Err(refused());
                }
            }
            _ => return Err(refused()),
        }
        drop(r);
        let admitted = self.start_bound_requests_store(
            input,
            entry.submitted_at(),
            registered,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(material)),
            None,
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(AgentStoreAdmitted {
            release: admitted.release,
        })
    }
    pub(crate) fn stop_agent_store(&self, binding: &Binding, reason: p::Reason, at: Instant) {
        binding.cancel(reason, at);
        let mut r = self.inner.lock();
        if r.prepared.as_ref().is_some_and(|p| {
            p.agent_store
                .as_ref()
                .is_some_and(|b| std::ptr::eq(b.as_ref(), binding))
        }) {
            self.inner.retire_prepared(&mut r, native_reason(reason));
        } else if let Some(owner) = r
            .active
            .as_ref()
            .filter(|a| {
                a.owner
                    .agent_store
                    .as_ref()
                    .is_some_and(|b| std::ptr::eq(b.as_ref(), binding))
            })
            .map(|a| a.owner.clone())
        {
            self.inner
                .stop_locked(&mut r, &owner, native_reason(reason), at);
        } else if !binding.scope.retired.load(Ordering::Acquire) {
            // A consumed Prepared lost before Session insertion has no positive
            // return witness. Its public tombstone is not native retirement.
            binding.unknown();
        }
    }
}
pub(crate) struct AgentStoreAdmitted {
    release: Option<oneshot::Sender<()>>,
}
impl AgentStoreAdmitted {
    pub(crate) fn release(self) {
        if let Some(go) = self.release {
            let _ = go.send(());
        }
    }
}

#[cfg(test)]
#[path = "saved_command_agent_store_tests.rs"]
mod tests;
