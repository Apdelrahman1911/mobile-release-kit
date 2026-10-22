//! Ordinary Prepare and Counter sibling of the existing publication delegation.
//! Ordinary Prepare never enters the Counter Facet. The SAME Facet,
//! PendingRead, source/Host proof, Supervisor and journal remain authoritative.
use super::*;
use action_delegation::dispatch as d;
impl PendingRead {
    fn select_counter<'a>(
        &self,
        view: &'a p::Status,
        marker: &str,
    ) -> Result<SelectedRow<'a>, BridgeError> {
        if !view.available || view.reason != p::Reason::None || !self.view(view) {
            return Err(refused(p::Reason::TargetChanged));
        }
        let record = view
            .pending
            .iter()
            .find(|v| v.summary.target().marker() == marker && v.summary.counter())
            .ok_or_else(|| refused(p::Reason::InvalidInput))?;
        Ok(SelectedRow {
            record,
            sha256: p::digest(&row_bytes(record)?),
        })
    }
}
impl ConnectionState {
    pub(crate) fn counter_agent_review(
        &self,
        input: d::Input,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        now: Instant,
        consumer: Option<&Arc<request::Entry>>,
    ) -> Result<action_delegation::Review, BridgeError> {
        let no = || refused(p::Reason::ConsentExpired);
        let st = &self.publication;
        if st.exhausted
            || st.active.is_some()
            || !st.view.available
            || st.view.reason != p::Reason::None
            || st.view.revision != input.revision()
            || st.agent_permission.is_some() && consumer.is_none()
        {
            return Err(no());
        }
        let capture = self.dispatch_capture(input, generation, root, binding, now)?;
        let input = &capture.input;
        let mut end = (now + Duration::from_millis(wire::INTENT_MS)).min(capture.credential_end);
        let (identity, data) = match input {
            d::Input::SetupPrepare(_) | d::Input::CounterPrepare(_) | d::Input::PublicationPending(_) => {
                if st.consent.is_some() {
                    return Err(no());
                }
                let v = wire::dispatch::RequestReference {
                    session_id: input.session().into(),
                    expected_revision: input.revision(),
                    request_sha256: input.hash()?,
                };
                (
                    st.agent_identity.clone(),
                    if matches!(input, d::Input::SetupPrepare(_)) {
                        wire::Review::SetupPrepare(v)
                    } else if matches!(input, d::Input::CounterPrepare(_)) {
                        wire::Review::CounterPrepare(v)
                    } else {
                        wire::Review::PublicationPending(v)
                    },
                )
            }
            d::Input::CounterCreate(args) => {
                let c = st.consent.as_ref().ok_or_else(no)?;
                if c.prepared.counter().is_none()
                    || c.counter_proof.is_none()
                    || !d::producer_ready(&c.producer)
                    || !action_delegation::origin(&c.agent, consumer)
                    || c.id != args.consent_id
                    || !args.confirm
                    || c.session_id != input.session()
                    || c.generation != generation
                    || &c.root != root
                    || !edit.matches(&c.stamp)
                    || now >= c.end
                {
                    return Err(no());
                }
                end = end.min(c.end);
                let data = action_delegation::review(
                    wire::Kind::CounterCreate,
                    &c.session_id,
                    &c.id,
                    input.revision(),
                    &c.prepared,
                    c.identity.clone(),
                    edit.stamp()?,
                    end,
                )?
                .data;
                (c.identity.clone(), data)
            }
            d::Input::CounterReconcile(args) => {
                let r = st.pending_read.as_ref().ok_or_else(no)?;
                if !action_delegation::origin(&r.agent, consumer)
                    || r.session_id != input.session()
                    || !r.binding(generation, root, edit, now)
                {
                    return Err(no());
                }
                let row = r.select_counter(&st.view, &args.marker)?;
                end = end.min(r.end);
                (
                    r.identity.clone(),
                    wire::Review::CounterReconcile(wire::PendingReference {
                        session_id: r.session_id.clone(),
                        expected_revision: input.revision(),
                        marker: args.marker.clone(),
                        record_sha256: row.sha256,
                    }),
                )
            }
            _ => return Err(no()),
        };
        if !data.valid() || !data.retained_fits() || !capture.retained_fits() {
            return Err(no());
        }
        Ok(action_delegation::Review {
            identity,
            stamp: edit.stamp()?,
            end,
            data,
            activity: None,
            dispatch: Some(capture),
        })
    }
    pub(crate) fn counter_agent_allow(
        &mut self,
        review: action_delegation::Review,
        scope: &Arc<request::NativeScope>,
    ) -> Result<(), BridgeError> {
        let no = || refused(p::Reason::ConsentExpired);
        if self.native_work_pending()
            || self.publication.agent_permission.is_some()
            || scope.review != review.data
            || !Arc::ptr_eq(&scope.identity, &review.identity)
            || scope.current(false).is_err()
        {
            return Err(no());
        }
        let capture = review.dispatch.ok_or_else(no)?;
        match &capture.input {
            d::Input::SetupPrepare(_) | d::Input::CounterPrepare(_) | d::Input::PublicationPending(_) => {
                if !Arc::ptr_eq(&self.publication.agent_identity, &review.identity) {
                    return Err(no());
                }
            }
            d::Input::CounterCreate(_) => {
                let c = self
                    .publication
                    .consent
                    .as_mut()
                    .filter(|c| {
                        c.prepared.counter().is_some()
                            && c.counter_proof.is_some()
                            && Arc::ptr_eq(&c.identity, &review.identity)
                            && d::producer_ready(&c.producer)
                    })
                    .ok_or_else(no)?;
                if c.agent.is_some() {
                    return Err(no());
                }
                c.agent = Some(Arc::downgrade(scope));
            }
            d::Input::CounterReconcile(v) => {
                let r = self
                    .publication
                    .pending_read
                    .as_mut()
                    .filter(|r| Arc::ptr_eq(&r.identity, &review.identity))
                    .ok_or_else(no)?;
                if r.agent.is_some()
                    || r.select_counter(&self.publication.view, &v.marker)?.sha256
                        != match &scope.review {
                            wire::Review::CounterReconcile(v) => v.record_sha256.clone(),
                            _ => return Err(no()),
                        }
                {
                    return Err(no());
                }
                r.agent = Some(Arc::downgrade(scope));
            }
            _ => return Err(no()),
        }
        self.publication.agent_permission = Some(d::Permission {
            scope: Arc::downgrade(scope),
            capture,
            stamp: review.stamp,
        });
        Ok(())
    }
    pub(crate) fn counter_agent_revoke(&mut self, scope: &Arc<request::NativeScope>) {
        if self
            .publication
            .agent_permission
            .as_ref()
            .and_then(|p| p.scope.upgrade())
            .is_some_and(|v| Arc::ptr_eq(&v, scope))
        {
            if let Some(p) = self.publication.agent_permission.take() {
                p.close();
            }
        }
        self.publication_agent_revoke(scope);
    }
    pub(crate) fn counter_agent_input(
        &self,
        entry: &Arc<request::Entry>,
    ) -> Result<d::Input, BridgeError> {
        let p = self
            .publication
            .agent_permission
            .as_ref()
            .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
        if p.scope
            .upgrade()
            .is_none_or(|s| !Arc::ptr_eq(&s, entry.scope()))
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        Ok(p.capture.input.clone())
    }
    pub(crate) fn counter_agent_entry(
        &mut self,
        command: &p::Command,
        entry: Option<&Arc<request::Entry>>,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        let no = || refused(p::Reason::ConsentExpired);
        let Some(entry) = entry else {
            if self.publication.agent_permission.is_some() {
                return Err(no());
            }
            return Ok(());
        };
        entry
            .current(false)
            .map_err(crate::asset_session::application_service::public_error)?;
        let input = self.counter_agent_input(entry)?;
        if !input.matches_counter(command) {
            return Err(no());
        }
        let review =
            self.counter_agent_review(input, generation, root, binding, edit, now, Some(entry))?;
        let permission = self.publication.agent_permission.as_ref().ok_or_else(no)?;
        if review.data != entry.scope().review
            || !Arc::ptr_eq(&review.identity, &entry.scope().identity)
            || review.dispatch.as_ref() != Some(&permission.capture)
            || !edit.matches(&permission.stamp)
        {
            return Err(no());
        }
        self.publication.agent_permission.take();
        Ok(())
    }
    pub(crate) fn counter_agent_return(
        &self,
        entry: &Arc<request::Entry>,
        id: &str,
        reason: p::Reason,
        effect: p::Effect,
    ) {
        let result = if reason == p::Reason::None {
            self.counter_compact(&entry.scope().review)
        } else {
            Ok(None)
        };
        let why = action_delegation::reason(
            &serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        );
        let effect = serde_json::to_value(effect)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok());
        match (result, effect) {
            (Ok(result), Some(effect)) => entry.dispatch_returned(id, why, effect, result),
            _ => entry.dispatch_returned(
                id,
                wire::Reason::NativeRefused,
                entry.scope().review.kind().go_effect(),
                None,
            ),
        }
    }
    fn counter_compact(
        &self,
        review: &wire::Review,
    ) -> Result<Option<wire::dispatch::Snapshot>, BridgeError> {
        use wire::dispatch::{Hex, Pending, Purpose, Snapshot};
        let no = || refused(p::Reason::ResponseInvalid);
        let v = &self.publication.view;
        Ok(Some(match review.kind() {
            wire::Kind::SetupPrepare => {
                let c = v.consent.as_ref().ok_or_else(no)?;
                let review = c.prepared.setup().ok_or_else(no)?;
                Snapshot::Prepared {
                    marker: Hex::parse(&c.id).ok_or_else(no)?,
                    prepared_sha256: Hex::parse(&d::hash(&c.prepared)?).ok_or_else(no)?,
                    source_sha: Hex::parse(&review.base_commit).ok_or_else(no)?,
                    platform: None,
                    stage: None,
                }
            }
            wire::Kind::CounterPrepare => {
                let c = v.consent.as_ref().ok_or_else(no)?;
                let review = c.prepared.counter().ok_or_else(no)?;
                Snapshot::Prepared {
                    marker: Hex::parse(&c.id).ok_or_else(no)?,
                    prepared_sha256: Hex::parse(&d::hash(&c.prepared)?).ok_or_else(no)?,
                    source_sha: Hex::parse(&review.base_commit).ok_or_else(no)?,
                    platform: None,
                    stage: None,
                }
            }
            wire::Kind::PublicationPending => {
                if v.pending.len() > 64 {
                    return Err(no());
                }
                let mut rows = Vec::with_capacity(v.pending.len());
                for r in &v.pending {
                    rows.push(Pending {
                        marker: Hex::parse(r.summary.target().marker()).ok_or_else(no)?,
                        run_id: None,
                        purpose: if r.summary.counter() {
                            Purpose::Counter
                        } else {
                            Purpose::Setup
                        },
                    });
                }
                Snapshot::Pending { rows }
            }
            wire::Kind::CounterCreate | wire::Kind::CounterReconcile => {
                let c = v.counter.as_ref().ok_or_else(no)?;
                let marker = match review {
                    wire::Review::CounterCreate(v) => &v.consent_id,
                    wire::Review::CounterReconcile(v) => &v.marker,
                    _ => return Err(no()),
                };
                Snapshot::Counter {
                    marker: Hex::parse(marker).ok_or_else(no)?,
                    commit_sha: Hex::parse(&c.commit).ok_or_else(no)?,
                    ledger_id: wire::dispatch::LedgerId::parse(&c.ledger_id).ok_or_else(no)?,
                    genesis_sha256: Hex::parse(&c.genesis_sha256).ok_or_else(no)?,
                }
            }
            _ => return Err(no()),
        }))
    }
}
impl d::Input {
    pub(crate) fn counter_command(&self) -> Result<p::Command, BridgeError> {
        Ok(match self {
            Self::SetupPrepare(v) => p::Command::Prepare(v.command_args()),
            Self::CounterPrepare(v) => p::Command::Prepare(v.clone()),
            Self::CounterCreate(v) => p::Command::Publish(v.clone()),
            Self::PublicationPending(v) => p::Command::Pending(v.clone()),
            Self::CounterReconcile(v) => p::Command::Reconcile(v.clone()),
            _ => return Err(BridgeError::invalid()),
        })
    }
    fn matches_counter(&self, c: &p::Command) -> bool {
        match (self, c) {
            (Self::SetupPrepare(a), p::Command::Prepare(b)) => a.command_args() == *b,
            (Self::CounterPrepare(a), p::Command::Prepare(b)) => a == b,
            (Self::CounterCreate(a), p::Command::Publish(b)) => a == b,
            (Self::PublicationPending(a), p::Command::Pending(b)) => a == b,
            (Self::CounterReconcile(a), p::Command::Reconcile(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
#[path = "github_setup_prepare_delegation_tests.rs"]
mod setup_prepare_tests;
