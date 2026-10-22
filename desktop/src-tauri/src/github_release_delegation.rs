//! Same release state: one capture, real private consent and returned record witness.
use super::*;
use crate::github_release_protocol as w;
use crate::github_release_session as state;
fn no() -> BridgeError {
    state::refused(w::Reason::TargetChanged)
}
impl ConnectionState {
    pub(crate) fn release_agent_review(
        &self,
        input: Input,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        now: Instant,
        consumer: Option<&Arc<r::Entry>>,
    ) -> Result<super::Review, BridgeError> {
        let st = &self.release;
        if st.exhausted
            || !st.view.available
            || st.view.reason != w::Reason::None
            || st.view.revision != input.revision()
            || st.agent_permission.is_some() && consumer.is_none()
        {
            return Err(no());
        }
        let capture = self.dispatch_capture(input, generation, root, binding, now)?;
        let input = &capture.input;
        let mut end = now
            .checked_add(Duration::from_millis(p::INTENT_MS))
            .ok_or_else(no)?
            .min(capture.credential_end);
        let (identity, data) = match input {
            Input::ReleasePrepare(_) | Input::ReleasePending(_) => {
                if st.consent.is_some() {
                    return Err(no());
                }
                let value = p::dispatch::RequestReference {
                    session_id: input.session().into(),
                    expected_revision: input.revision(),
                    request_sha256: input.hash()?,
                };
                (
                    st.agent_identity.clone(),
                    if matches!(input, Input::ReleasePrepare(_)) {
                        p::Review::ReleasePrepare(value)
                    } else {
                        p::Review::ReleasePending(value)
                    },
                )
            }
            Input::ReleaseDispatch(args) => {
                let c = st.consent.as_ref().ok_or_else(no)?;
                if !producer_ready(&c.producer)
                    || !super::origin(&c.agent, consumer)
                    || c.session_id != args.session_id
                    || c.generation != generation
                    || &c.root != root
                    || now >= c.end
                    || c.prepared.target.marker != args.consent_id
                    || !args.matches_review(&c.prepared)
                    || c.prepared.target.account_id != capture.account
                    || c.prepared.target.repository_id != capture.repository
                    || c.prepared.target.repository != capture.coordinate
                    || c.prepared.target.project_binding != capture.binding
                {
                    return Err(no());
                }
                end = end.min(c.end);
                (
                    c.identity.clone(),
                    p::Review::ReleaseDispatch(p::PreparedReference {
                        session_id: input.session().into(),
                        consent_id: args.consent_id.clone(),
                        expected_revision: input.revision(),
                        prepared_sha256: hash(&c.prepared)?,
                    }),
                )
            }
            Input::ReleaseObserve(args) => {
                let record = st.record(&args.marker).ok_or_else(no)?;
                let witness = st.agent_records.as_ref().ok_or_else(no)?;
                if !witness.current(
                    &st.view.pending,
                    st.view.operation.as_ref().map(|o| o.id.as_str()),
                    input.session(),
                    generation,
                    root,
                    edit,
                    now,
                ) || record.run_id != args.run_id
                    || record.prepared.target.account_id != capture.account
                    || record.prepared.target.repository_id != capture.repository
                    || record.prepared.target.repository != capture.coordinate
                    || record.prepared.target.project_binding != capture.binding
                {
                    return Err(no());
                }
                end = end.min(witness.end);
                (
                    witness.identity.clone(),
                    p::Review::ReleaseObserve(p::dispatch::RecordReference {
                        session_id: input.session().into(),
                        expected_revision: input.revision(),
                        marker: args.marker.clone(),
                        record_sha256: hash(record)?,
                        observe: args.observe,
                        run_id: args.run_id.clone(),
                    }),
                )
            }
            _ => return Err(no()),
        };
        if !data.valid() || !data.retained_fits() || !capture.retained_fits() {
            return Err(no());
        }
        Ok(super::Review {
            identity,
            stamp: edit.stamp()?,
            end,
            data,
            activity: None,
            dispatch: Some(capture),
        })
    }
    pub(crate) fn release_agent_allow(
        &mut self,
        review: super::Review,
        scope: &Arc<r::NativeScope>,
    ) -> Result<(), BridgeError> {
        if self.native_work_pending()
            || self.release.agent_permission.is_some()
            || scope.review != review.data
            || !Arc::ptr_eq(&scope.identity, &review.identity)
            || scope.current(false).is_err()
        {
            return Err(no());
        }
        let capture = review.dispatch.ok_or_else(no)?;
        match &capture.input {
            Input::ReleaseDispatch(_) => {
                let c = self.release.consent.as_mut().ok_or_else(no)?;
                if !Arc::ptr_eq(&c.identity, &review.identity)
                    || c.agent.is_some()
                    || !producer_ready(&c.producer)
                {
                    return Err(no());
                }
                c.agent = Some(Arc::downgrade(scope));
            }
            Input::ReleasePrepare(_) | Input::ReleasePending(_) => {
                if !Arc::ptr_eq(&review.identity, &self.release.agent_identity) {
                    return Err(no());
                }
            }
            Input::ReleaseObserve(_) => {
                if self
                    .release
                    .agent_records
                    .as_ref()
                    .is_none_or(|r| !Arc::ptr_eq(&review.identity, &r.identity))
                {
                    return Err(no());
                }
            }
            _ => return Err(no()),
        }
        self.release.agent_permission = Some(Permission {
            scope: Arc::downgrade(scope),
            capture,
            stamp: review.stamp,
        });
        Ok(())
    }
    pub(crate) fn release_agent_revoke(&mut self, scope: &Arc<r::NativeScope>) {
        if self
            .release
            .agent_permission
            .as_ref()
            .and_then(|p| p.scope.upgrade())
            .is_some_and(|s| Arc::ptr_eq(&s, scope))
        {
            if let Some(p) = self.release.agent_permission.take() {
                p.close();
            }
            if self
                .release
                .consent
                .as_ref()
                .and_then(|c| c.agent.as_ref())
                .and_then(Weak::upgrade)
                .is_some_and(|s| Arc::ptr_eq(&s, scope))
            {
                self.release.revoke_consent();
            }
        }
    }
    pub(crate) fn release_agent_input(&self, entry: &Arc<r::Entry>) -> Result<Input, BridgeError> {
        let p = self.release.agent_permission.as_ref().ok_or_else(no)?;
        if p.scope
            .upgrade()
            .is_none_or(|s| !Arc::ptr_eq(&s, entry.scope()))
        {
            return Err(no());
        }
        Ok(p.capture.input.clone())
    }
    pub(crate) fn release_agent_entry(
        &mut self,
        command: &w::Command,
        entry: Option<&Arc<r::Entry>>,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: Option<&SavedEditGuard<'_>>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        let Some(entry) = entry else {
            if self.release.agent_permission.is_some() {
                return Err(no());
            }
            if matches!(command, w::Command::Dispatch(_))
                && self
                    .release
                    .consent
                    .as_ref()
                    .is_some_and(|c| c.agent.is_some() || !producer_ready(&c.producer))
            {
                return Err(no());
            }
            return Ok(());
        };
        entry
            .current(false)
            .map_err(crate::asset_session::application_service::public_error)?;
        let input = self.release_agent_input(entry)?;
        if !input.matches_release(command) {
            return Err(no());
        }
        let edit = edit.ok_or_else(no)?;
        let review =
            self.release_agent_review(input, generation, root, binding, edit, now, Some(entry))?;
        let permission = self.release.agent_permission.as_ref().ok_or_else(no)?;
        if review.data != entry.scope().review
            || !Arc::ptr_eq(&review.identity, &entry.scope().identity)
            || review.dispatch.as_ref() != Some(&permission.capture)
            || !edit.matches(&permission.stamp)
        {
            return Err(no());
        }
        // Consumes only the installed input before the original method consumes
        // Consent/admission. The original Entry+gate retain all later failures.
        self.release.agent_permission.take();
        Ok(())
    }
}
impl Input {
    pub(crate) fn release_command(&self) -> Result<w::Command, BridgeError> {
        Ok(match self {
            Self::ReleasePrepare(v) => w::Command::Prepare(v.clone()),
            Self::ReleaseDispatch(v) => w::Command::Dispatch(v.clone()),
            Self::ReleasePending(v) => w::Command::Pending(v.clone()),
            Self::ReleaseObserve(v) => {
                let a = w::ObserveArgs {
                    session_id: v.session_id.clone(),
                    expected_revision: v.expected_revision,
                    marker: v.marker.clone(),
                };
                if v.observe == p::dispatch::Observe::Track {
                    w::Command::Track(a)
                } else {
                    w::Command::Reconcile(a)
                }
            }
            _ => return Err(no()),
        })
    }
    fn matches_release(&self, command: &w::Command) -> bool {
        match (self, command) {
            (Self::ReleasePrepare(a), w::Command::Prepare(b)) => a == b,
            (Self::ReleaseDispatch(a), w::Command::Dispatch(b)) => a == b,
            (Self::ReleasePending(a), w::Command::Pending(b)) => a == b,
            (Self::ReleaseObserve(a), w::Command::Track(b))
            | (Self::ReleaseObserve(a), w::Command::Reconcile(b)) => {
                a.session_id == b.session_id
                    && a.expected_revision == b.expected_revision
                    && a.marker == b.marker
                    && (a.observe == p::dispatch::Observe::Track)
                        == matches!(command, w::Command::Track(_))
            }
            _ => false,
        }
    }
}
pub(crate) fn returned(
    active: &state::Active,
    view: &w::Status,
    reason: w::Reason,
    effect: w::Effect,
) -> Result<Option<p::dispatch::Snapshot>, BridgeError> {
    use p::dispatch::{Hex, Pending, Purpose, Snapshot};
    if reason != w::Reason::None {
        return Ok(None);
    }
    let value = match active.request.kind() {
        w::Kind::Prepare => {
            let prepared = view.prepared.as_ref().ok_or_else(no)?;
            Some(Snapshot::Prepared {
                marker: Hex::parse(&prepared.target.marker).ok_or_else(no)?,
                prepared_sha256: Hex::parse(&hash(prepared)?).ok_or_else(no)?,
                source_sha: Hex::parse(&prepared.source_sha).ok_or_else(no)?,
                platform: Some(match prepared.target.platform {
                    w::Platform::Android => p::dispatch::Platform::Android,
                    w::Platform::Ios => p::dispatch::Platform::Ios,
                }),
                stage: Some(match prepared.target.selection.stage {
                    w::Stage::Candidate => p::dispatch::Stage::Candidate,
                    w::Stage::ExternalTesting => p::dispatch::Stage::ExternalTesting,
                    w::Stage::ProductionSubmit => p::dispatch::Stage::ProductionSubmit,
                }),
            })
        }
        w::Kind::Pending => {
            if view.pending.len() > 64 {
                return Err(no());
            }
            let mut rows = Vec::with_capacity(view.pending.len());
            for r in &view.pending {
                rows.push(Pending {
                    marker: Hex::parse(&r.prepared.target.marker).ok_or_else(no)?,
                    run_id: r
                        .run_id
                        .as_ref()
                        .map(|s| s.parse::<u64>().map_err(|_| no()))
                        .transpose()?,
                    purpose: Purpose::Release,
                });
            }
            Some(Snapshot::Pending { rows })
        }
        w::Kind::Track | w::Kind::Reconcile => {
            let run = view.run.as_ref().ok_or_else(no)?;
            let action = active.request.action.as_ref().ok_or_else(no)?;
            Some(Snapshot::Observed {
                marker: Hex::parse(&action.target.marker).ok_or_else(no)?,
                run_id: Some(run.id.parse().map_err(|_| no())?),
                attempt: u16::try_from(run.attempt).map_err(|_| no())?,
                status: serde_json::from_value(serde_json::to_value(run.status).map_err(|_| no())?)
                    .map_err(|_| no())?,
                conclusion: serde_json::from_value(
                    serde_json::to_value(run.conclusion).map_err(|_| no())?,
                )
                .map_err(|_| no())?,
            })
        }
        w::Kind::Dispatch => {
            if effect != w::Effect::Accepted {
                return Err(no());
            }
            None
        }
    };
    Ok(value)
}
impl ConnectionState {
    pub(crate) fn release_agent_return(
        &mut self,
        active: &mut state::Active,
        reason: w::Reason,
        effect: w::Effect,
        settled: Instant,
        now: Instant,
    ) {
        // This call is placed AFTER original Connection control/currentness and
        // retirement. The producer remains unusable until relay AND history ACK.
        if reason == w::Reason::None
            && matches!(
                active.request.kind(),
                w::Kind::Pending | w::Kind::Dispatch | w::Kind::Track | w::Kind::Reconcile
            )
        {
            if let (Some(stamp), Some(private)) = (active.stamp.take(), &self.private) {
                let end = (settled + Duration::from_millis(p::INTENT_MS))
                    .min(private.clock.end)
                    .min(
                        active
                            .agent
                            .as_ref()
                            .map_or(private.clock.end, |e| e.scope().read.end()),
                    );
                if now < end {
                    if let Ok(digest) = hash(&self.release.view.pending) {
                        self.release.agent_records = Some(Records {
                            identity: Arc::new(()),
                            original: active.ticket.operation_id().into(),
                            session: active.session_id.clone(),
                            generation: active.generation,
                            root: active.root.clone(),
                            stamp,
                            end,
                            digest,
                            producer: active
                                .agent
                                .as_ref()
                                .map(|e| Producer::new(e, active.ticket.operation_id())),
                        });
                    }
                }
            }
        }
        let Some(entry) = &active.agent else { return };
        let snapshot = returned(active, &self.release.view, reason, effect);
        let mapped = super::reason(
            &serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        );
        if mapped == p::Reason::CleanupUnknown {
            entry.unknown(mapped);
            return;
        }
        let effect =
            serde_json::from_value(serde_json::to_value(effect).unwrap_or(serde_json::Value::Null));
        match (snapshot, effect) {
            (Ok(snapshot), Ok(effect)) => {
                entry.dispatch_returned(active.ticket.operation_id(), mapped, effect, snapshot)
            }
            _ => entry.dispatch_returned(
                active.ticket.operation_id(),
                p::Reason::NativeRefused,
                entry.scope().review.kind().go_effect(),
                None,
            ),
        }
    }
}
