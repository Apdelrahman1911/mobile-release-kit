//! Optional attachment to the SAME Saved Prepared/Session, made before its
//! first publication. No new native process, lifetime, credential or journal.
use super::*;
use crate::{service_store_prepare_protocol as flow, service_store_requests::preparation as queue};

#[derive(Clone)]
pub(crate) enum Input {
    Access(store_wire::Context),
    Candidate(prepare_wire::Context),
    Execute(execute_wire::Context),
}
impl Input {
    pub fn parse(kind: flow::Kind, value: &serde_json::Value) -> Result<Self, BridgeError> {
        let input = if kind.candidate_upload().is_some() {
            Self::Execute(execute_wire::prepare(value)?.context())
        } else if kind.prepares_intent() {
            Self::Candidate(prepare_wire::prepare(value)?.context())
        } else {
            Self::Access(store_wire::prepare(value)?.context())
        };
        if input.selection()?.kind != kind {
            return Err(refused());
        }
        Ok(input)
    }
    pub fn project(&self) -> &str {
        match self {
            Self::Access(c) => &c.project_id,
            Self::Candidate(c) => &c.project_id,
            Self::Execute(c) => &c.project_id,
        }
    }
    fn context(&self) -> Context {
        match self {
            Self::Access(c) => Context::LocalStorePreflight(c.clone()),
            Self::Candidate(c) => Context::LocalStorePrepare(c.clone()),
            Self::Execute(c) => Context::LocalStoreExecute(c.clone()),
        }
    }
    pub fn selection(&self) -> Result<flow::Selection, BridgeError> {
        selection(&self.context())
    }
}
fn selection(c: &Context) -> Result<flow::Selection, BridgeError> {
    use flow::Kind as K;
    let (kind, config, v, candidate, later, execute) = match c {
        Context::LocalStorePreflight(c) => {
            use store_wire::AccessPlatform as P;
            let kind = match (c.platform, c.query.is_none(), c.ios_record.is_some()) {
                (P::Android, true, false) => K::AndroidAccess,
                (P::Ios, true, false) => K::IosAccess,
                (P::Android, false, false) if store_wire::play_versions::selected(c) => {
                    K::AndroidVersions
                }
                (P::Ios, false, false) if store_wire::store_versions::selected(c) => K::IosVersions,
                (P::Both, false, true) if store_wire::paired_versions::selected(c) => {
                    K::PairedVersions
                }
                _ => return Err(refused()),
            };
            (
                kind,
                p::Content {
                    bytes: c.saved_config.bytes,
                    sha256: c.saved_config.sha256.clone(),
                },
                version(&c.saved_version),
                None,
                None,
                None,
            )
        }
        Context::LocalStorePrepare(c) => (
            match (c.platform, c.later.as_ref().map(|l| l.stage)) {
                (prepare_wire::Platform::Android, None) => K::AndroidCandidate,
                (prepare_wire::Platform::Ios, None) => K::IosCandidate,
                (prepare_wire::Platform::Android, Some(prepare_wire::StoreStage::ExternalTesting)) => K::AndroidExternalTesting,
                (prepare_wire::Platform::Ios, Some(prepare_wire::StoreStage::ExternalTesting)) => K::IosExternalTesting,
                (prepare_wire::Platform::Android, Some(prepare_wire::StoreStage::ProductionSubmit)) => K::AndroidProductionSubmit,
                (prepare_wire::Platform::Ios, Some(prepare_wire::StoreStage::ProductionSubmit)) => K::IosProductionSubmit,
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
            c.later.as_ref().map(|l| flow::StageSelection {
                stage: match l.stage {
                    prepare_wire::StoreStage::ExternalTesting => flow::Stage::ExternalTesting,
                    prepare_wire::StoreStage::ProductionSubmit => flow::Stage::ProductionSubmit,
                },
                predecessor_operation_id: l.predecessor_operation_id.clone(),
                predecessor_receipt_sha256: l.predecessor_receipt_sha256.clone(),
            }),
            None,
        ),
        Context::LocalStoreExecute(c) if c.later.is_none() && c.stage_operation_id.is_none() => (
            match c.platform {
                execute_wire::Platform::Android => K::AndroidCandidateUpload,
                execute_wire::Platform::Ios => K::IosCandidateUpload,
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
            None,
            Some(flow::ExecuteSelection { intent_sha256: c.intent_sha256.clone() }),
        ),
        _ => return Err(refused()),
    };
    let value = flow::Selection {
        kind,
        saved_config: config,
        saved_version: v,
        candidate,
        later,
        execute,
    };
    if !value.bounded_capacity() {
        return Err(refused());
    }
    Ok(value)
}
pub(crate) struct Binding {
    pub entry: Arc<queue::PrepareEntry>,
    owner: Weak<Inner>,
    context: Context,
    registration: u32,
    root: RegisteredRoot,
    material: Weak<SelectedStoreMaterial>,
    review: flow::Review,
    expires: Instant,
    consumed: AtomicBool,
}
impl Binding {
    pub(in crate::saved_command_owner) fn stop_at(
        &self,
        now: Instant,
    ) -> Option<(Reason, Instant)> {
        let _ = self
            .entry
            .scope
            .current(self.consumed.load(Ordering::Acquire), now);
        match self.entry.scope.control.first() {
            Ok(v) => v.map(|(r, at)| (native_reason(r), at)),
            Err(_) => Some((
                Reason::CleanupUnknown,
                self.entry.scope.control.uncertain_at(now),
            )),
        }
    }
    pub(in crate::saved_command_owner) fn read_end(&self) -> Instant {
        self.entry.scope.read.end()
    }
    fn matches(&self, inner: &Arc<Inner>, p: &Prepared) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && p.registration == self.registration
            && p.project == self.root
            && p.projection.context == self.context
            && p.expires == self.expires
            && p.projection.operation_id == self.review.operation.operation_id.as_str()
            && p.projection.owner_generation == self.review.operation.owner_generation.as_str()
            && matches!(&p.material, Some(PrivateSigningMaterial::Store(m)) if self.material.as_ptr() == Arc::as_ptr(m))
    }
    fn publish(&self, projection: &RunProjection, revision: u32, retired: bool) {
        let result = (|| {
            if projection.context != self.context
                || projection.operation_id != self.review.operation.operation_id.as_str()
                || projection.owner_generation != self.review.operation.owner_generation.as_str()
                || projection.phase == Phase::Unknown
            {
                return Err(refused());
            }
            let (state, outcome, result) = if retired {
                if projection.phase != Phase::Terminal {
                    return Err(refused());
                }
                let outcome = match projection.outcome.ok_or_else(refused)? {
                    Outcome::Complete => p::Outcome::Complete,
                    Outcome::Failed => p::Outcome::Failed,
                    Outcome::Refused => p::Outcome::Refused,
                    Outcome::Cancelled => p::Outcome::Cancelled,
                    Outcome::TimedOut => p::Outcome::TimedOut,
                    Outcome::Unknown => return Err(refused()),
                };
                let report = if outcome == p::Outcome::Complete {
                    Some(project_report(
                        projection.result.as_ref().ok_or_else(refused)?,
                        &self.context,
                        &self.entry.scope.selection,
                        &self.review,
                    )?)
                } else {
                    None
                };
                (
                    match outcome {
                        p::Outcome::Complete => s::OperationState::Succeeded,
                        p::Outcome::Cancelled => s::OperationState::Cancelled,
                        _ => s::OperationState::Failed,
                    },
                    Some(outcome),
                    report,
                )
            } else {
                (
                    match projection.phase {
                        Phase::AwaitingConsent => s::OperationState::Prepared,
                        Phase::Stopping => s::OperationState::CancellationRequested,
                        Phase::Starting | Phase::Running | Phase::Terminal => {
                            s::OperationState::Running
                        }
                        _ => return Err(refused()),
                    },
                    None,
                    None,
                )
            };
            Ok(queue::Native {
                operation: p::Operation {
                    operation_id: self.review.operation.operation_id.clone(),
                    owner_generation: self.review.operation.owner_generation.clone(),
                    status_revision: revision,
                },
                state,
                reason: reason(projection.reason, &self.entry.scope.control),
                outcome,
                result,
                retired,
            })
        })();
        match result {
            Ok(v) => self.entry.native(v),
            Err(_) => self.entry.unknown(p::Reason::CleanupUnknown),
        }
    }
}
fn project_report(
    t: &Terminal,
    context: &Context,
    selection: &flow::Selection,
    review: &flow::Review,
) -> Result<flow::Report, BridgeError> {
    if let Some(old) = flow::ordinary_review(selection, review) {
        return report(t, &old).map(|report| flow::Report::Ordinary { report });
    }
    if selection.kind.stage().is_some() {
        return project_stage_report(t, context, selection, review);
    }
    let (Terminal::LocalStorePreflight(t), Context::LocalStorePreflight(context)) = (t, context)
    else {
        return Err(refused());
    };
    // The SAME original decoder validated context, closure and exact query
    // before this actual-retirement callback. This projection grants nothing.
    let bytes = crate::edit_protocol::bounded(
        t.result.as_ref().ok_or_else(refused)?,
        store_wire::RESPONSE_LIMIT,
    )?;
    let result: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let current = result.get("currentVersions").ok_or_else(refused)?;
    let projected = match selection.kind {
        flow::Kind::IosVersions => serde_json::json!({"platform":"ios","current":current}),
        flow::Kind::AndroidVersions => serde_json::json!({"platform":"android","current":current}),
        flow::Kind::PairedVersions => {
            serde_json::json!({"platform":"both","android":current.get("android").ok_or_else(refused)?,"ios":current.get("ios").ok_or_else(refused)?})
        }
        _ => return Err(refused()),
    };
    let bounded = crate::edit_protocol::bounded(&projected, flow::STATUS_LIMIT)?;
    let mut inventory: crate::service_store_inventory_protocol::Inventory =
        serde_json::from_slice(&bounded).map_err(|_| refused())?;
    if t.current_inventory_data(context).is_none() {
        // A decodable Complete result is not necessarily a current inventory:
        // the original gate also requires the exact command/dispatch cut and,
        // for Both, two observed sides. Preserve real inconclusive/edit-warning
        // DATA, but never promote a partial result to positive attribution.
        use crate::service_store_inventory_protocol::{Android, Inventory, Ios, Observation};
        fn ios(v: &mut Ios) {
            if v.observation == Observation::Observed {
                v.observation = Observation::Inconclusive;
                v.revision = None;
                v.counts = None;
                v.max_build = None;
                v.marketing_version = None;
            }
        }
        fn android(v: &mut Android) {
            if v.observation == Observation::Observed {
                v.observation = Observation::Inconclusive;
                v.revision = None;
                v.counts = None;
                v.max_build = None;
                v.marketing_version = None;
            }
        }
        match &mut inventory {
            Inventory::Ios { current } => ios(current),
            Inventory::Android { current } => android(current),
            Inventory::Both { android: a, ios: i } => {
                android(a);
                ios(i);
            }
        }
    }
    let report = flow::Report::CurrentVersions { inventory };
    if !report.valid_for(selection, review) {
        return Err(refused());
    }
    Ok(report)
}
fn project_stage_report(
    terminal: &Terminal,
    context: &Context,
    selected: &flow::Selection,
    review: &flow::Review,
) -> Result<flow::Report, BridgeError> {
    let (Terminal::LocalStorePrepare(t), Context::LocalStorePrepare(c)) = (terminal, context) else {
        return Err(refused());
    };
    if c.later.is_none() || selection(context)? != *selected {
        return Err(refused());
    }
    // Only the original decoded terminal reaches the actual Saved retirement
    // callback. Recheck its native UUID4 mapping, then project a closed subset;
    // no caller/status row supplies an operation, secret or old finality.
    let actual_uuid = crate::android_build_protocol::candidate_uuid(review.operation.operation_id.as_str())
        .ok_or_else(refused)?;
    let bytes = crate::edit_protocol::bounded(t.result.as_ref().ok_or_else(refused)?, prepare_wire::STATUS_LIMIT)?;
    let result: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let intent = result.get("preparedIntent").ok_or_else(refused)?;
    let (platform, scope) = match c.platform {
        prepare_wire::Platform::Android => (p::Platform::Android, "local-android-store-stage-prepare"),
        prepare_wire::Platform::Ios => (p::Platform::Ios, "local-ios-store-stage-prepare"),
    };
    if result.get("scope").and_then(serde_json::Value::as_str) != Some(scope)
        || intent.get("operationId").and_then(serde_json::Value::as_str) != Some(actual_uuid.as_str())
        || intent.get("version") != Some(&serde_json::json!({"name":c.saved_version.name,"build":c.saved_version.build}))
    {
        return Err(refused());
    }
    let projected = serde_json::json!({
        "platform":platform,"headSequence":result.get("headSequence").ok_or_else(refused)?,
        "stage":intent.get("stage").ok_or_else(refused)?,"operationId":actual_uuid,
        "candidateOperationId":intent.get("candidateOperationId").ok_or_else(refused)?,
        "candidateSha256":intent.get("candidateSha256").ok_or_else(refused)?,
        "predecessorOperationId":intent.get("predecessorOperationId").ok_or_else(refused)?,
        "predecessorReceiptSha256":intent.get("predecessorReceiptSha256").ok_or_else(refused)?,
        "intentSha256":intent.get("intentSha256").ok_or_else(refused)?,
        "storePreconditionSha256":intent.get("storePreconditionSha256").ok_or_else(refused)?,
        "destination":intent.get("destination").ok_or_else(refused)?,
        "limitations":intent.get("limitations").ok_or_else(refused)?,
    });
    let bounded = crate::edit_protocol::bounded(&projected, flow::STATUS_LIMIT)?;
    let report = flow::Report::StagePrepare {
        report: serde_json::from_slice(&bounded).map_err(|_| refused())?,
    };
    if !report.valid_for(selected, review) || !report.bounded_capacity() {
        return Err(refused());
    }
    Ok(report)
}
pub(in crate::saved_command_owner) fn link(
    entry: Option<Arc<queue::PrepareEntry>>,
    inner: &Arc<Inner>,
    c: &Context,
    registration: u32,
    root: &RegisteredRoot,
    id: &str,
    generation: &str,
    revision: u32,
    expires: Instant,
    material: Option<&PrivateSigningMaterial>,
) -> Result<Option<Arc<Binding>>, BridgeError> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    let Some(PrivateSigningMaterial::Store(material)) = material else {
        return Err(refused());
    };
    if entry.scope.selection != selection(c)?
        || entry.scope.runtime_id != c.project_id()
        || expires > entry.scope.expires
        || !PrivateSigningMaterial::Store(material.clone()).matches(c, registration, root)
    {
        return Err(refused());
    }
    let review = flow::Review {
        review_id: s::Id::parse(id).map_err(|_| refused())?,
        operation: p::Operation {
            operation_id: s::Id::parse(id).map_err(|_| refused())?,
            owner_generation: s::Id::parse(generation).map_err(|_| refused())?,
            status_revision: revision,
        },
    };
    entry
        .attach(review.clone(), expires)
        .map_err(|_| refused())?;
    Ok(Some(Arc::new(Binding {
        entry,
        owner: Arc::downgrade(inner),
        context: c.clone(),
        registration,
        root: root.clone(),
        material: Arc::downgrade(material),
        review,
        expires,
        consumed: AtomicBool::new(false),
    })))
}
pub(in crate::saved_command_owner) fn installed(p: &Prepared) -> Result<(), BridgeError> {
    if let Some(link) = &p.agent_store_preparation {
        link.entry.installed().map_err(|_| {
            link.entry.unknown(p::Reason::CleanupUnknown);
            refused()
        })?;
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn start_matches(
    p: &Prepared,
    e: Option<&Arc<queue::PrepareEntry>>,
) -> bool {
    match (&p.agent_store_preparation, e) {
        (None, None) => true,
        (Some(link), Some(e)) => {
            Arc::ptr_eq(&link.entry, e)
                && !link.consumed.load(Ordering::Acquire)
                && p.projection.context == link.context
                && p.agent_store.is_none()
                && e.start_at().is_ok()
        }
        _ => false,
    }
}
pub(in crate::saved_command_owner) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    if let Some(link) = &p.agent_store_preparation {
        if link.consumed.swap(true, Ordering::AcqRel) {
            return Err(refused());
        }
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if let Some(b) = &a.owner.agent_store_preparation {
            b.publish(&a.projection, r.revision, false);
        }
    } else if let Some(p) = &r.prepared {
        if let Some(b) = &p.agent_store_preparation {
            b.publish(&p.projection, r.revision, false);
        }
    }
}
pub(in crate::saved_command_owner) fn retired_prepared(p: &Prepared, why: Reason, revision: u32) {
    if let Some(b) = &p.agent_store_preparation {
        b.publish(&retire(p.projection.clone(), why), revision, true);
    }
}
pub(in crate::saved_command_owner) fn retired(a: &Active, revision: u32) {
    if let Some(b) = &a.owner.agent_store_preparation {
        b.publish(&a.projection, revision, true);
    }
}
impl SavedCommandOwner {
    /// BEFORE the outer Document's destructive material/currentness tail.
    /// Ordinary None is unchanged; a foreign caller cannot cancel a linked one.
    pub(crate) fn ordinary_store_start_allowed(
        &self,
        id: &str,
        generation: &str,
    ) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if !r.prepared.as_ref().is_some_and(|p| {
            p.projection.operation_id == id
                && p.projection.owner_generation == generation
                && p.agent_store.is_none()
                && p.agent_store_preparation.is_none()
        }) {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn prepare_agent_store_original(
        &self,
        input: &Input,
        entry: Arc<queue::PrepareEntry>,
        registration: u32,
        root: RegisteredRoot,
        gate: store_wire::Availability,
        material: Arc<SelectedStoreMaterial>,
    ) -> Result<(), BridgeError> {
        let context = input.context();
        self.require_domain(context.domain())?;
        if matches!(input, Input::Access(_)) {
            self.inner.lock().store_versions.invalidate();
        }
        let status = self.prepare_bound_store_preparation(
            context,
            registration,
            root,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(material)),
            None,
            None,
            None,
            None,
            Some(entry),
        )?;
        match input {
            Input::Access(_) => {
                status.store()?;
            }
            Input::Candidate(_) => {
                status.prepare()?;
            }
            Input::Execute(_) => {
                status.execute()?;
            }
        }
        Ok(())
    }
    pub(crate) fn store_preparation_current(
        &self,
        entry: &Arc<queue::PrepareEntry>,
        review: &flow::Review,
    ) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        let r = self.inner.lock();
        let p = r.prepared.as_ref().ok_or_else(refused)?;
        let link = p.agent_store_preparation.as_ref().ok_or_else(refused)?;
        if r.disabled
            || r.document_lost
            || r.stopping
            || self.inner.poisoned.load(Ordering::SeqCst)
            || r.revision < review.operation.status_revision
            || p.projection.phase != Phase::AwaitingConsent
            || !p.projection.intent_usable
            || link.review != *review
            || !Arc::ptr_eq(&link.entry, entry)
            || !link.matches(&self.inner, p)
            || link.consumed.load(Ordering::Acquire)
            || Instant::now() >= p.expires
        {
            return Err(refused());
        }
        entry.current(false).map_err(|_| refused())?;
        match &p.material {
            Some(PrivateSigningMaterial::Store(m)) => Ok(m.clone()),
            _ => Err(refused()),
        }
    }
    pub(crate) fn start_agent_store_original(
        &self,
        entry: &Arc<queue::PrepareEntry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: store_wire::Availability,
        material: Arc<SelectedStoreMaterial>,
        budget: Option<&crate::asset_session::ExecuteMemoryAdmission<'_>>,
    ) -> Result<AgentStoreAdmitted, BridgeError> {
        let review = entry.installed_review().map_err(|_| refused())?;
        let held = self.store_preparation_current(entry, &review)?;
        if !Arc::ptr_eq(&held, &material) {
            return Err(refused());
        }
        let (consent, kind) = {
            let r = self.inner.lock();
            let p = r.prepared.as_ref().ok_or_else(refused)?;
            if !start_matches(p, Some(entry)) {
                return Err(refused());
            }
            if selection(&p.projection.context)? != entry.scope.selection {
                return Err(refused());
            }
            match &p.projection.context {
                Context::LocalStorePreflight(c) => (
                    match entry.scope.selection.kind {
                        flow::Kind::AndroidAccess | flow::Kind::IosAccess if c.query.is_none() => {
                            c.platform.consent()
                        }
                        flow::Kind::IosVersions if store_wire::store_versions::selected(c) => {
                            store_wire::store_versions::CONSENT
                        }
                        flow::Kind::AndroidVersions if store_wire::play_versions::selected(c) => {
                            store_wire::play_versions::CONSENT
                        }
                        flow::Kind::PairedVersions if store_wire::paired_versions::selected(c) => {
                            store_wire::paired_versions::CONSENT
                        }
                        _ => return Err(refused()),
                    },
                    p::Kind::AccessCheck,
                ),
                Context::LocalStorePrepare(c) if entry.scope.selection.kind.prepares_intent() => (c.consent(), p::Kind::CandidatePrepare),
                Context::LocalStoreExecute(c) if entry.scope.selection.kind.candidate_upload().is_some()
                    && c.later.is_none() && c.stage_operation_id.is_none() => (c.consent(), p::Kind::Execute),
                _ => return Err(refused()),
            }
        };
        let args = serde_json::json!({"operationId":review.operation.operation_id.as_str(), "ownerGeneration":review.operation.owner_generation.as_str(), "consentVersion":consent});
        if (kind == p::Kind::Execute) != budget.is_some() {
            return Err(refused());
        }
        let consent_matches = match kind {
            p::Kind::AccessCheck => material.accepts_access_consent(&store_wire::start(&args)?),
            p::Kind::CandidatePrepare => material.accepts_prepare_consent(&prepare_wire::start(&args)?),
            p::Kind::Execute => material.accepts_execute_consent(&execute_wire::start(&args)?),
            p::Kind::Reconcile => false,
        };
        if !consent_matches { return Err(refused()); }
        let witness = if kind == p::Kind::AccessCheck {
            material.version_inventory_witness()?
        } else {
            None
        };
        let input = Start {
            operation_id: review.operation.operation_id.as_str().into(),
            owner_generation: review.operation.owner_generation.as_str().into(),
        };
        let admitted = self.start_bound_store_preparation(
            input,
            entry.start_at().map_err(|_| refused())?,
            registered,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(material)),
            budget,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(entry),
        )?;
        if let Some(witness) = witness {
            let mut r = self.inner.lock();
            let owner = r
                .active
                .as_ref()
                .filter(|a| {
                    a.owner.id == review.operation.operation_id.as_str()
                        && a.owner.generation == review.operation.owner_generation.as_str()
                })
                .map(|a| a.owner.clone())
                .ok_or_else(refused)?;
            if !r.store_versions.arm(&owner, witness) {
                self.inner
                    .stop_locked(&mut r, &owner, Reason::ContextChanged, Instant::now());
                return Err(refused());
            }
        }
        Ok(AgentStoreAdmitted {
            release: admitted.release,
        })
    }
    pub(crate) fn stop_store_preparation(
        &self,
        entry: &Arc<queue::PrepareEntry>,
        why: p::Reason,
        at: Instant,
    ) {
        entry.cancel(why, at);
        let mut r = self.inner.lock();
        if r.prepared
            .as_ref()
            .and_then(|p| p.agent_store_preparation.as_ref())
            .is_some_and(|b| Arc::ptr_eq(&b.entry, entry))
        {
            self.inner.retire_prepared(&mut r, native_reason(why));
        } else if let Some(owner) = r
            .active
            .as_ref()
            .filter(|a| {
                a.owner
                    .agent_store_preparation
                    .as_ref()
                    .is_some_and(|b| Arc::ptr_eq(&b.entry, entry))
            })
            .map(|a| a.owner.clone())
        {
            self.inner
                .stop_locked(&mut r, &owner, native_reason(why), at);
        } else if entry
            .status()
            .is_ok_and(|s| s.prepared.is_some() && s.settlement == s::Settlement::Pending)
        {
            entry.unknown(p::Reason::CleanupUnknown);
        }
    }
}

#[cfg(test)]
#[path = "saved_command_agent_store_prepare_tests.rs"]
mod tests;
