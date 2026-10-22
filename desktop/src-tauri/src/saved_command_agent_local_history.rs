//! Start-only private link on the SAME LocalHistory Saved Prepared/Session.
//! Only original native retirement publishes final DATA; no journal/key owner here.
use super::*;
use crate::{
    service_local_history_protocol as p, service_protocol as s,
    service_store_requests::history as requests,
};
use std::sync::{OnceLock, Weak};
use serde::Deserialize;
fn refused() -> BridgeError {
    crate::local_release_history_owner::unavailable()
}
pub(super) fn review(
    c: &Context,
    id: &str,
    generation: &str,
    revision: u32,
) -> Result<p::Review, BridgeError> {
    let Context::LocalReleaseHistory(c) = c else {
        return Err(refused());
    };
    let kind = match c.action {
        history_wire::Action::Enroll => p::Kind::Enroll,
        history_wire::Action::Verify => p::Kind::Verify,
        history_wire::Action::ReviewInputs => p::Kind::ReviewInputs,
        history_wire::Action::ReviewPrepared => p::Kind::ReviewPrepared,
        history_wire::Action::ReviewExecution => p::Kind::ReviewExecution,
        history_wire::Action::ReviewReconcile => p::Kind::ReviewReconcile,
        history_wire::Action::ReviewRecovery => p::Kind::ReviewRecovery,
        history_wire::Action::ReviewStagePrepared => p::Kind::ReviewStagePrepared,
        history_wire::Action::ReviewStageExecution => p::Kind::ReviewStageExecution,
        history_wire::Action::ReviewExternalReadiness => p::Kind::ReviewExternalReadiness,
        history_wire::Action::AbandonInputs => return Err(refused()),
    };
    let platform = match c.platform {
        None => None,
        Some(history_wire::CandidatePlatform::Ios) => Some(p::Platform::Ios),
        Some(history_wire::CandidatePlatform::Android) => Some(p::Platform::Android),
    };
    let r = p::Review {
        kind,
        platform,
        candidate_operation_id: c.candidate_operation_id.clone(),
        stage_operation_id: c.stage_operation_id.clone(),
        operation_id: s::Id::parse(id).map_err(|_| refused())?,
        owner_generation: s::Id::parse(generation).map_err(|_| refused())?,
        status_revision: revision,
    };
    if !r.valid() {
        return Err(refused());
    }
    Ok(r)
}
/// No strong NativeContext/Consent/Session is retained by the service graph.
pub(crate) struct Approval {
    owner: Weak<Inner>,
    consent: Weak<crate::asset_session::LocalHistoryConsent>,
    witness: Arc<()>,
    project_id: String,
    registration: u32,
    root: RegisteredRoot,
    expires: Instant,
    review: p::Review,
    preparation: Option<Weak<requests::preparation::Entry>>,
}
impl Approval {
    pub(crate) fn preparation(&self)->Option<Arc<requests::preparation::Entry>> {self.preparation.as_ref().and_then(Weak::upgrade)}
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn project(&self) -> &str {
        &self.project_id
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn consent(&self) -> Option<Arc<crate::asset_session::LocalHistoryConsent>> {
        self.consent.upgrade()
    }
    pub(crate) fn witness(&self) -> Weak<()> {
        Arc::downgrade(&self.witness)
    }
    pub(crate) fn matches_root(&self, g: u32, r: &RegisteredRoot) -> bool {
        self.registration == g && self.root == *r
    }
    fn matches(&self, inner: &Arc<Inner>, p: &Prepared) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && p.registration == self.registration
            && p.project == self.root
            && p.expires == self.expires
            && p.local_history
                .as_ref()
                .is_some_and(|c| self.consent.as_ptr() == Arc::as_ptr(c))
            && p.projection.context.project_id() == self.project_id
            && review(
                &p.projection.context,
                &p.projection.operation_id,
                &p.projection.owner_generation,
                self.review.status_revision,
            )
            .is_ok_and(|r| r == self.review)
    }
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    scope: Arc<requests::Scope>,
    // Small identity DATA, not the Prepared/Session or a native resource Arc.
    _witness: Arc<()>,
    entry: OnceLock<Arc<requests::Entry>>,
    latest: Mutex<Option<requests::NativeData>>,
    consumed: AtomicBool,
}
impl Binding {
    pub(crate) fn scope(&self) -> &Arc<requests::Scope> {
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
pub(super) fn reason(r: Reason, control: &requests::Control) -> p::Reason {
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
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReturnedResult {
    schema_version: u32,
    scope: String,
    enrolled: bool,
    head_sequence: u32,
    history: Vec<p::HistoryRow>,
    limitations: [p::Limitation; 3],
    #[serde(default)]
    candidate_inputs: Option<ReturnedInputs>,
    #[serde(default)] prepared_intent: Option<serde_json::Value>,
    #[serde(default)] execution_receipt: Option<serde_json::Value>,
    #[serde(default)] reconciliation_receipt: Option<serde_json::Value>,
    #[serde(default)] readiness_receipt: Option<serde_json::Value>,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReturnedInputs {
    operation_id: String,
    candidate_sha256: String,
    source_commit: String,
    source_tree: String,
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    bundle_id: Option<String>,
    version: p::Version,
    files: [p::File; 3],
    #[serde(default)]
    archive: Option<p::Archive>,
    observation: String,
    prior_create_finality: String,
}
fn reviewed_files(native:&ReturnedResult,r:&p::Review)->Result<Option<Box<crate::service_local_history_prepare_protocol::ReviewedFiles>>,BridgeError>{
    use crate::service_local_history_prepare_protocol::{ReviewedFiles,FilesKind,FilesObservation,Stage,PriorFinality,Destination};
    let options=[&native.prepared_intent,&native.execution_receipt,&native.reconciliation_receipt,&native.readiness_receipt];
    let (index,kind,observation,finality)=match r.kind {
        p::Kind::ReviewPrepared|p::Kind::ReviewReconcile|p::Kind::ReviewStagePrepared=>(0,FilesKind::Prepared,FilesObservation::Prepared,"priorPrepareFinality"),
        p::Kind::ReviewExecution|p::Kind::ReviewStageExecution=>(1,FilesKind::Execution,FilesObservation::Execution,"priorExecutionFinality"),
        p::Kind::ReviewRecovery=>(2,FilesKind::Reconciliation,FilesObservation::Reconciliation,"priorExecutionFinality"),
        p::Kind::ReviewExternalReadiness=>(3,FilesKind::ExternalReadiness,FilesObservation::ExternalReadiness,"priorExecutionFinality"),
        _=>return if options.iter().all(|v|v.is_none()){Ok(None)}else{Err(refused())},
    };
    if options.iter().enumerate().any(|(i,v)|i!=index&&v.is_some()){return Err(refused());}
    let v=options[index].as_ref().ok_or_else(refused)?;
    let text=|key:&str|v.get(key).and_then(serde_json::Value::as_str).map(str::to_owned).ok_or_else(refused);
    let optional=|key:&str|->Result<Option<String>,BridgeError>{v.get(key).map(|v|v.as_str().map(str::to_owned).ok_or_else(refused)).transpose()};
    if v.get(finality).and_then(serde_json::Value::as_str)!=Some("not-established")
        ||v.get("observation").and_then(serde_json::Value::as_str)!=Some(match observation {
            FilesObservation::Prepared=>"current-prepared-files-only",FilesObservation::Execution=>"current-execution-files-only",
            FilesObservation::Reconciliation=>"current-recovery-files-only",FilesObservation::ExternalReadiness=>"current-external-readiness-files-only"}) {return Err(refused());}
    let d=v.get("destination").ok_or_else(refused)?;
    let stage=if kind==FilesKind::ExternalReadiness {Some(Stage::ExternalTesting)} else {
        v.get("stage").map(|v|Stage::deserialize(v).map_err(|_|refused())).transpose()?
    };
    let out=ReviewedFiles{kind,operation_id:text("operationId")?,candidate_sha256:text("candidateSha256")?,intent_sha256:text("intentSha256")?,
        receipt_sha256:optional("receiptSha256")?,source_commit:text("sourceCommit")?,source_tree:text("sourceTree")?,
        application:text(if r.platform==Some(p::Platform::Ios){"bundleId"}else{"applicationId"})?,
        version:p::Version::deserialize(v.get("version").ok_or_else(refused)?).map_err(|_|refused())?,
        destination:Destination{channel:d.get("channel").and_then(serde_json::Value::as_str).map(str::to_owned).ok_or_else(refused)?,
            release_status:d.get("releaseStatus").map(|v|v.as_str().map(str::to_owned).ok_or_else(refused)).transpose()?,
            automatic_release:d.get("automaticRelease").map(|v|v.as_bool().ok_or_else(refused)).transpose()?},
        stage,candidate_operation_id:optional("candidateOperationId")?,predecessor_operation_id:optional("predecessorOperationId")?,
        predecessor_receipt_sha256:optional("predecessorReceiptSha256")?,execution_receipt_sha256:optional("executionReceiptSha256")?,
        observation,prior_finality:PriorFinality::NotEstablished};
    if !out.bounded(r){return Err(refused());}Ok(Some(Box::new(out)))
}
fn report(t: &Terminal, r: &p::Review) -> Result<p::Report, BridgeError> {
    let Terminal::LocalReleaseHistory(t) = t else {
        return Err(refused());
    };
    // ONLY the same already-validated native retired result. One finite encoded
    // buffer and typed copy; no imported journal/receipt can enter this function.
    let bytes = crate::edit_protocol::bounded(
        t.result.as_ref().ok_or_else(refused)?,
        history_wire::STATUS_LIMIT,
    )?;
    let native: ReturnedResult = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if native.schema_version != 1 || native.scope != "local-release-history" {
        return Err(refused());
    }
    let reviewed_files=reviewed_files(&native,r)?;
    let candidate_inputs = match native.candidate_inputs {
        None => None,
        Some(c) => {
            let application = match (r.platform, c.application_id, c.bundle_id) {
                (None, Some(app), None) => app,
                (Some(p::Platform::Ios), None, Some(app)) => app,
                _ => return Err(refused()),
            };
            Some(p::Inputs {
                operation_id: c.operation_id,
                candidate_sha256: c.candidate_sha256,
                source_commit: c.source_commit,
                source_tree: c.source_tree,
                application,
                version: c.version,
                files: c.files,
                archive: c.archive,
                observation: c.observation,
                prior_create_finality: c.prior_create_finality,
            })
        }
    };
    let result = p::Report {
        enrolled: native.enrolled,
        head_sequence: native.head_sequence,
        history: native.history,
        candidate_inputs,
        reviewed_files,
        limitations: native.limitations,
    };
    if !result.bounded(r) {
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
    match (&p.agent_history, entry) {
        (None, None) => p.agent_history_preparation.is_none(),
        (Some(link), Some(entry)) => {
            link.entry.get().is_some_and(|e| Arc::ptr_eq(e, entry))
                && Arc::ptr_eq(link.scope(), entry.scope())
                && !link.consumed.load(Ordering::Acquire)
                && link
                    .approval
                    .owner
                    .upgrade()
                    .is_some_and(|o| link.approval.matches(&o, p))
        }
        _ => false,
    }
}
pub(super) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    if let Some(link) = &p.agent_history {
        if link.consumed.swap(true, Ordering::AcqRel) {
            return Err(refused());
        }
    }
    Ok(())
}
pub(super) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if let Some(b) = &a.owner.agent_history {
            b.publish(&a.projection, r.revision, false);
        }
    } else if let Some(p) = &r.prepared {
        if let Some(b) = &p.agent_history {
            b.publish(&p.projection, r.revision, false);
        }
    }
}
pub(super) fn retired_prepared(p: &Prepared, reason: Reason, revision: u32) {
    history_preparation::retired(p,reason);
    if let Some(b) = &p.agent_history {
        b.publish(&retire(p.projection.clone(), reason), revision, true);
    }
}
pub(super) fn retired(a: &Active, revision: u32) {
    if let Some(b) = &a.owner.agent_history {
        b.publish(&a.projection, revision, true);
    }
}
impl SavedCommandOwner {
    pub(crate) fn history_approval(
        &self,
        kind: p::Kind,
        operation: &s::Id,
        generation: &s::Id,
        revision: u32,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.history_approval_from(kind,operation,generation,revision,None)
    }
    pub(crate) fn history_approval_from(&self,kind:p::Kind,operation:&s::Id,generation:&s::Id,revision:u32,
        original:Option<&Arc<requests::preparation::Entry>>)->Result<Arc<Approval>,BridgeError>{
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        let p = r
            .prepared
            .as_ref()
            .filter(|p| {
                p.agent_history.is_none()
                    && match (&p.agent_history_preparation,original) {
                        (None,None)=>true,
                        (Some(l),Some(e))=>Arc::ptr_eq(&l.entry,e)&&e.ready(),
                        _=>false,
                    }
                    && p.projection.phase == Phase::AwaitingConsent
                    && p.projection.intent_usable
                    && r.revision == revision
                    && p.projection.operation_id == operation.as_str()
                    && p.projection.owner_generation == generation.as_str()
            })
            .ok_or_else(refused)?;
        let review = review(
            &p.projection.context,
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
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            consent: Arc::downgrade(p.local_history.as_ref().ok_or_else(refused)?),
            witness: Arc::new(()),
            project_id: p.projection.context.project_id().into(),
            registration: p.registration,
            root: p.project.clone(),
            expires: p.expires,
            preparation:original.map(Arc::downgrade),
            review,
        }))
    }
    pub(crate) fn history_approval_current(&self, a: &Approval) -> bool {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        !self.inner.poisoned.load(Ordering::SeqCst)
            && !r.disabled
            && !r.document_lost
            && !r.stopping
            && r.prepared
                .as_ref()
                .is_some_and(|p| a.matches(&self.inner, p))
    }
    pub(crate) fn bind_history_approval(
        &self,
        approval: Arc<Approval>,
        scope: Arc<requests::Scope>,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if self.inner.poisoned.load(Ordering::SeqCst)
            || r.disabled
            || r.document_lost
            || r.stopping
            || r.revision != approval.review.status_revision
            || scope.review != approval.review
            || scope.witness.as_ptr() != Arc::as_ptr(&approval.witness)
            || scope.expires != approval.expires.min(scope.read.end())
            || scope.current(false, Instant::now()).is_err()
        {
            return Err(refused());
        }
        let p = r
            .prepared
            .as_mut()
            .filter(|p| p.agent_history.is_none() && approval.matches(&self.inner, p))
            .ok_or_else(refused)?;
        match (&p.agent_history_preparation,approval.preparation.as_ref(),scope.preparation.as_ref()) {
            (None,None,None)=>{},
            (Some(l),Some(a),Some(b)) if a.as_ptr()==Arc::as_ptr(&l.entry)&&b.as_ptr()==Arc::as_ptr(&l.entry)
                && Arc::ptr_eq(&scope.read,&l.entry.scope().read)=>{
                l.entry.begin_handoff(&scope.review).map_err(|_|refused())?;
            },
            _=>return Err(refused()),
        }
        let link = Arc::new(Binding {
            _witness: approval.witness.clone(),
            approval,
            scope,
            entry: OnceLock::new(),
            latest: Mutex::new(None),
            consumed: AtomicBool::new(false),
        });
        p.agent_history = Some(link.clone());
        Ok(link)
    }
    pub(crate) fn start_agent_history(
        &self,
        entry: &Arc<requests::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: history_wire::Availability,
    ) -> Result<AgentHistoryAdmitted, BridgeError> {
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        let input = Start {
            operation_id: entry.scope().review.operation_id.as_str().into(),
            owner_generation: entry.scope().review.owner_generation.as_str().into(),
        };
        // The same original private LocalHistoryConsent is still required; no public
        // Review/CLI field constructs it. Common Start then consumes exactly once.
        self.prepared_history_consent(&input.operation_id, &input.owner_generation)?;
        let admitted = self.start_bound_local_history(
            input,
            entry.submitted_at(),
            registered,
            Availability::from_history(gate),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(AgentHistoryAdmitted {
            release: admitted.release,
        })
    }
    pub(crate) fn stop_agent_history(&self, binding: &Binding, reason: p::Reason, at: Instant) {
        binding.cancel(reason, at);
        let mut r = self.inner.lock();
        if r.prepared.as_ref().is_some_and(|p| {
            p.agent_history
                .as_ref()
                .is_some_and(|b| std::ptr::eq(b.as_ref(), binding))
        }) {
            self.inner.retire_prepared(&mut r, native_reason(reason));
        } else if let Some(owner) = r
            .active
            .as_ref()
            .filter(|a| {
                a.owner
                    .agent_history
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
pub(crate) struct AgentHistoryAdmitted {
    release: Option<oneshot::Sender<()>>,
}
impl AgentHistoryAdmitted {
    pub(crate) fn release(self) {
        if let Some(go) = self.release {
            let _ = go.send(());
        }
    }
}

pub(super) fn backing_bytes() -> Option<usize> {
    use std::mem::size_of;
    // The same Binding may overlap an outgoing and replacing Doc grant. Its
    // latest Report has a closed8KiB cell+heap cap. No strong Consent/Context.
    let n = 2usize.checked_mul(size_of::<Approval>() + size_of::<Binding>() + 8192 + 4096 + 512)?;
    (n <= 32 * 1024).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(action: history_wire::Action) -> Context {
        Context::LocalReleaseHistory(history_wire::Context {
            project_id: "p1".into(),
            execution_mode: history_wire::ExecutionMode::Local,
            action,
            candidate_operation_id: None,
            stage_operation_id: None,
            platform: None,
        })
    }
    fn projected(context: Context) -> RunProjection {
        RunProjection {
            agent_build: None,
            agent_local_check: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context,
            phase: Phase::AwaitingConsent,
            intent_usable: true,
            outcome: None,
            reason: Reason::None,
            result: None,
            stage: None,
        }
    }
    #[test]
    fn local_history_native_review_never_relabels_other_history_actions() {
        for action in [history_wire::Action::Enroll, history_wire::Action::Verify] {
            let c = context(action);
            let r = review(&c, &"a".repeat(32), &"b".repeat(32), 1).unwrap();
            assert!(r.platform.is_none() && r.candidate_operation_id.is_none());
        }
        let mut c = match context(history_wire::Action::ReviewInputs) {
            Context::LocalReleaseHistory(c) => c,
            _ => unreachable!(),
        };
        c.candidate_operation_id = Some("12345678-1234-4234-8234-123456789abc".into());
        assert!(review(
            &Context::LocalReleaseHistory(c.clone()),
            &"a".repeat(32),
            &"b".repeat(32),
            1
        )
        .is_ok());
        c.platform = Some(history_wire::CandidatePlatform::Ios);
        assert_eq!(
            review(
                &Context::LocalReleaseHistory(c.clone()),
                &"a".repeat(32),
                &"b".repeat(32),
                1
            )
            .unwrap()
            .platform,
            Some(p::Platform::Ios)
        );
        for action in [history_wire::Action::ReviewPrepared,history_wire::Action::ReviewExecution,history_wire::Action::ReviewReconcile]{
            c.action=action;assert!(review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).is_ok());
        }
        c.action=history_wire::Action::ReviewRecovery;
        assert!(review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).is_err());
        c.platform=None;assert!(review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).is_ok());
        c.action=history_wire::Action::AbandonInputs;
        assert!(review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).is_err());
        c.candidate_operation_id=None;c.stage_operation_id=Some("12345678-1234-4234-8234-123456789abc".into());
        for platform in [history_wire::CandidatePlatform::Android,history_wire::CandidatePlatform::Ios]{
            c.platform=Some(platform);
            for action in [history_wire::Action::ReviewStagePrepared,history_wire::Action::ReviewStageExecution]{
                c.action=action;let r=review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).unwrap();
                assert!(r.stage_operation_id.is_some()&&r.candidate_operation_id.is_none());
            }
            c.action=history_wire::Action::ReviewExternalReadiness;
            assert_eq!(review(&Context::LocalReleaseHistory(c.clone()),&"a".repeat(32),&"b".repeat(32),1).is_ok(),platform==history_wire::CandidatePlatform::Ios);
        }

    }
    #[test]
    fn local_history_terminal_projection_requires_actual_retirement_and_original_ids() {
        let mut p = projected(context(history_wire::Action::Verify));
        let r = review(&p.context, &p.operation_id, &p.owner_generation, 1).unwrap();
        let control = requests::Control::new();
        p.phase = Phase::Terminal;
        p.outcome = Some(Outcome::Cancelled);
        p.reason = Reason::Cancelled;
        p.intent_usable = false;
        let pending = projection(&p, 2, false, &r, &control).unwrap();
        assert!(!pending.retired && pending.outcome.is_none() && pending.result.is_none());
        let retired = projection(&p, 3, true, &r, &control).unwrap();
        assert!(retired.retired);
        assert_eq!(retired.outcome, Some(p::Outcome::Cancelled));
        p.phase = Phase::Unknown;
        assert!(projection(&p, 4, true, &r, &control).is_err());
        p.phase = Phase::Terminal;
        p.operation_id = "c".repeat(32);
        assert!(projection(&p, 4, true, &r, &control).is_err());
    }
    #[test]
    fn local_history_actual_original_result_projects_only_public_current_history() {
        let c = match context(history_wire::Action::Verify) {
            Context::LocalReleaseHistory(c) => c,
            _ => unreachable!(),
        };
        // Actual closed native Terminal decoder; no child process/join is fabricated.
        let raw = serde_json::json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none","result":{"schemaVersion":1,"scope":"local-release-history","enrolled":true,"headSequence":1,"history":[],"limitations":p::LIMITATIONS},"lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}});
        let mut decoder = history_wire::Decoder::new();
        let mut frame = |sequence: u32, kind: &str, payload: serde_json::Value| {
            let mut bytes=serde_json::to_vec(&serde_json::json!({"protocol":history_wire::PROTOCOL,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),"sequence":sequence,"kind":kind,"payload":payload})).unwrap();
            bytes.push(b'\n');
            decoder.decode(
                &bytes,
                &"a".repeat(32),
                &"b".repeat(32),
                &c,
                &"c".repeat(32),
                &"d".repeat(64),
            )
        };
        frame(
            0,
            "accepted",
            serde_json::json!({"schemaVersion":1,"context":c}),
        )
        .unwrap();
        frame(1, "lease-ready", serde_json::json!({})).unwrap();
        frame(
            2,
            "history-head",
            serde_json::json!({"sequence":1,"sha256":"e".repeat(64)}),
        )
        .unwrap();
        let t = match frame(3, "terminal", raw).unwrap() {
            history_wire::Frame::Terminal(t) => t,
            _ => panic!("terminal expected"),
        };
        assert!(decoder.finish());
        let r = review(
            &Context::LocalReleaseHistory(c),
            &"a".repeat(32),
            &"b".repeat(32),
            1,
        )
        .unwrap();
        let result = report(&Terminal::LocalReleaseHistory(t), &r).unwrap();
        assert!(result.bounded(&r));
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert!(value.get("key").is_none());
        assert!(value["candidateInputs"].is_null());
        assert!(backing_bytes().is_some());
    }
    #[test]
    fn actual_native_prepared_file_decoder_projects_only_bounded_current_file_summary(){
        use serde_json::json;
        let id="12345678-1234-4234-8234-123456789abc";
        let c=history_wire::Context{project_id:"runtime-p1".into(),execution_mode:history_wire::ExecutionMode::Local,action:history_wire::Action::ReviewPrepared,platform:None,candidate_operation_id:Some(id.into()),stage_operation_id:None};
        let summary=json!({"operationId":id,"candidateSha256":"a".repeat(64),"intentSha256":"b".repeat(64),"storePreconditionSha256":"c".repeat(64),"sourceCommit":"d".repeat(40),"sourceTree":"e".repeat(40),"applicationId":"dev.example.app","version":{"name":"1.2","build":12},"destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-16T20:00:00Z","limitations":["non-publishing","prepare-not-execute","temporary-edit-may-expire","current-bundle-not-historical-finality","saved-inputs-not-atomic"],"observation":"current-prepared-files-only","priorPrepareFinality":"not-established"});
        let raw=json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none","result":{"schemaVersion":1,"scope":"local-release-history","enrolled":true,"headSequence":5,"history":[{"operationId":id,"phase":"prepared","recoveryRequired":true}],"preparedIntent":summary,"limitations":p::LIMITATIONS},"lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}});
        let mut decoder=history_wire::Decoder::new();let mut frame=|sequence:u32,kind:&str,payload:serde_json::Value|{
            let mut bytes=serde_json::to_vec(&json!({"protocol":history_wire::PROTOCOL,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),"sequence":sequence,"kind":kind,"payload":payload})).unwrap();bytes.push(b'\n');
            decoder.decode(&bytes,&"a".repeat(32),&"b".repeat(32),&c,&"c".repeat(32),&"d".repeat(64))};
        frame(0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap();frame(1,"lease-ready",json!({})).unwrap();frame(2,"history-head",json!({"sequence":5,"sha256":"e".repeat(64)})).unwrap();
        let t=match frame(3,"terminal",raw).unwrap(){history_wire::Frame::Terminal(t)=>t,_=>panic!("terminal")};assert!(decoder.finish());
        let selected=review(&Context::LocalReleaseHistory(c),&"a".repeat(32),&"b".repeat(32),1).unwrap();let mut public=report(&Terminal::LocalReleaseHistory(t),&selected).unwrap();assert!(public.bounded(&selected));
        let value=serde_json::to_value(&public).unwrap();assert_eq!(value["reviewedFiles"]["application"],"dev.example.app");assert_eq!(value["reviewedFiles"]["priorFinality"],"not-established");assert!(value["candidateInputs"].is_null());
        for field in ["storePreconditionSha256","observedAt","authorizationId","appStoreAppId","rawJournal"]{assert!(value["reviewedFiles"].get(field).is_none());}
        let files=public.reviewed_files.as_mut().unwrap();let original=files.application.clone();files.application.reserve(4096);assert_eq!(files.application,original);assert!(!public.bounded(&selected));
    }

}
