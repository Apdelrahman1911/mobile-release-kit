//! A closed facet of the original Setup state. MAIN retains comparison inputs,
//! not credentials; only the original Doc can re-prove the variable loan.
use super::*;
use crate::{github_setup_protocol as w, github_setup_session as state};
use serde::de::{MapAccess, Visitor};
fn no() -> BridgeError { state::refused(w::Reason::TargetChanged) }
fn object<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    struct V<T>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>> Visitor<'de> for V<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("named object") }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(V(std::marker::PhantomData))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Selection {
    #[serde(rename = "actions_enabled")]
    ActionsEnabled { enabled: bool },
    #[serde(rename = "workflow_token_policy")]
    WorkflowTokenPolicy {
        #[serde(rename = "defaultWorkflowPermissions")] default_workflow_permissions: w::Permission,
        #[serde(rename = "canApprovePullRequestReviews")] can_approve_pull_request_reviews: bool,
    },
    #[serde(rename = "environment_protection")]
    Environment(w::EnvironmentSelection),
    #[serde(rename = "environment_variable")]
    Variable {
        mode: w::VariableMode, stage: w::EnvironmentStage, requirement: w::VariableRequirement,
        #[serde(deserialize_with = "object")] source: w::SecretRecord,
    },
}
impl Selection {
    pub(crate) fn native(&self) -> w::Selection {
        match self {
            Self::ActionsEnabled { enabled } => w::Selection::ActionsEnabled { enabled: *enabled },
            Self::WorkflowTokenPolicy { default_workflow_permissions, can_approve_pull_request_reviews } => w::Selection::WorkflowTokenPolicy {
                default_workflow_permissions: *default_workflow_permissions, can_approve_pull_request_reviews: *can_approve_pull_request_reviews },
            Self::Environment(v) => w::Selection::Environment(v.clone()),
            Self::Variable { mode, stage, requirement, source } => w::Selection::Variable(w::VariableSelection {
                mode: *mode, stage: *stage, requirement: *requirement, source: source.clone() }),
        }
    }
    pub(crate) fn heap(&self) -> usize {
        match self {
            Self::Environment(v) => v.reviewer_login.as_ref().map_or(0, String::capacity),
            Self::Variable { source, .. } => source.record_id.capacity(),
            _ => 0,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) selection: Selection,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Apply {
    pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) consent_id: String, pub(crate) confirm: bool,
}
fn original(session: &str, revision: u32) -> bool {
    crate::protocol::valid_id(session) && revision > 0 && revision <= w::LAST_REVISION
}
impl Prepare {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision) && self.expected_connection_revision > 0
            && self.expected_connection_revision <= w::LAST_REVISION && self.selection.native().valid()
    }
    pub(crate) fn heap(&self) -> Option<usize> { self.session_id.capacity().checked_add(self.selection.heap()) }
}
impl Apply {
    pub(crate) fn valid(&self) -> bool {
        original(&self.session_id, self.expected_revision) && p::hex(&self.consent_id, 32) && self.confirm
    }
    pub(crate) fn heap(&self) -> Option<usize> { self.session_id.capacity().checked_add(self.consent_id.capacity()) }
}
impl Input {
    pub(crate) fn remote_command(&self) -> Result<w::Command, BridgeError> {
        Ok(match self {
            Self::RemoteSetupPrepare(v) if v.valid() => w::Command::Prepare(w::PrepareArgs {
                session_id: v.session_id.clone(), expected_revision: v.expected_revision,
                expected_connection_revision: v.expected_connection_revision, selection: v.selection.native() }),
            Self::RemoteSetupApply(v) if v.valid() => w::Command::Apply(w::ApplyArgs {
                session_id: v.session_id.clone(), expected_revision: v.expected_revision,
                consent_id: v.consent_id.clone(), confirm: v.confirm }),
            _ => return Err(no()),
        })
    }
    fn matches_remote(&self, command: &w::Command) -> bool {
        match (self, command) {
            (Self::RemoteSetupPrepare(a), w::Command::Prepare(b)) => a.session_id == b.session_id
                && a.expected_revision == b.expected_revision && a.expected_connection_revision == b.expected_connection_revision
                && a.selection.native() == b.selection,
            (Self::RemoteSetupApply(a), w::Command::Apply(b)) => a.session_id == b.session_id
                && a.expected_revision == b.expected_revision && a.consent_id == b.consent_id && a.confirm == b.confirm,
            _ => false,
        }
    }
}
impl ConnectionState {
    // This is a borrow of the actual Consent's material, never a fresh lookalike.
    pub(crate) fn remote_agent_material(&self) -> Option<&Arc<crate::asset_session::GitHubVariableMaterial>> {
        self.setup.consent.as_ref()?.material.as_ref()?.variable()
    }
    pub(crate) fn remote_agent_review(
        &self, input: Input, generation: u32, root: &RegisteredRoot, binding: &str,
        edit: &SavedEditGuard<'_>, now: Instant, consumer: Option<&Arc<r::Entry>>,
        variable: Option<crate::asset_session::RemoteSetupVariablePins>,
    ) -> Result<super::Review, BridgeError> {
        let st = &self.setup;
        if st.exhausted || !st.view.available || st.view.reason != w::Reason::None
            || st.view.revision != input.revision() || st.agent_permission.is_some() && consumer.is_none()
        { return Err(no()); }
        let mut capture = self.dispatch_capture(input, generation, root, binding, now)?;
        capture.remote_variable = variable;
        let mut end = now.checked_add(Duration::from_millis(p::INTENT_MS)).ok_or_else(no)?.min(capture.credential_end);
        let (identity, data) = match &capture.input {
            Input::RemoteSetupPrepare(v) => {
                if st.consent.is_some() || matches!(v.selection, Selection::Variable { .. }) != capture.remote_variable.is_some() {
                    return Err(no());
                }
                (st.agent_identity.clone(), p::Review::RemoteSetupPrepare(p::dispatch::RequestReference {
                    session_id: v.session_id.clone(), expected_revision: v.expected_revision, request_sha256: capture.input.hash()? }))
            }
            Input::RemoteSetupApply(v) => {
                let c = st.consent.as_ref().ok_or_else(no)?;
                let target = c.prepared.target();
                if matches!(target.selection, w::Selection::Secret(_)) || !c.prepared.valid()
                    || !producer_ready(&c.producer) || !super::origin(&c.agent, consumer)
                    || c.session_id != v.session_id || c.generation != generation || &c.root != root
                    || !edit.matches(&c.edit_stamp) || now >= c.end || c.id != v.consent_id || !v.confirm
                    || target.account_id != capture.account || target.repository_id != capture.repository
                    || target.repository != capture.coordinate || target.project_binding != capture.binding
                    || matches!(target.selection, w::Selection::Variable(_)) != capture.remote_variable.is_some()
                    || capture.remote_variable.as_ref().is_some_and(|pins| c.material.as_ref().and_then(state::ConsentMaterial::variable).is_none_or(|m| !pins.matches(m)))
                { return Err(no()); }
                end = end.min(c.end);
                (c.identity.clone(), p::Review::RemoteSetupApply(p::PreparedReference {
                    session_id: v.session_id.clone(), consent_id: v.consent_id.clone(),
                    expected_revision: v.expected_revision, prepared_sha256: hash(&c.prepared)? }))
            }
            _ => return Err(no()),
        };
        if !data.valid() || !data.retained_fits() || !capture.retained_fits() { return Err(no()); }
        Ok(super::Review { identity, stamp: edit.stamp()?, end, data,
            activity: None, dispatch: Some(capture), enrollment: None, operation: None })
    }
    pub(crate) fn remote_agent_allow(&mut self, review: super::Review, scope: &Arc<r::NativeScope>) -> Result<(), BridgeError> {
        if self.native_work_pending() || self.setup.agent_permission.is_some() || scope.review != review.data
            || !Arc::ptr_eq(&scope.identity, &review.identity) || scope.current(false).is_err() { return Err(no()); }
        let capture = review.dispatch.ok_or_else(no)?;
        match &capture.input {
            Input::RemoteSetupPrepare(_) => {
                if !Arc::ptr_eq(&self.setup.agent_identity, &review.identity) { return Err(no()); }
            }
            Input::RemoteSetupApply(_) => {
                let c = self.setup.consent.as_mut().ok_or_else(no)?;
                if !Arc::ptr_eq(&c.identity, &review.identity) || c.agent.is_some() || !producer_ready(&c.producer)
                    || matches!(c.prepared.target().selection, w::Selection::Secret(_)) { return Err(no()); }
                c.agent = Some(Arc::downgrade(scope));
            }
            _ => return Err(no()),
        }
        self.setup.agent_permission = Some(Permission { scope: Arc::downgrade(scope), capture, stamp: review.stamp });
        Ok(())
    }
    pub(crate) fn remote_agent_revoke(&mut self, scope: &Arc<r::NativeScope>) {
        if self.setup.agent_permission.as_ref().and_then(|p| p.scope.upgrade()).is_some_and(|s| Arc::ptr_eq(&s, scope)) {
            if let Some(p) = self.setup.agent_permission.take() { p.close(); }
        }
        if self.setup.consent.as_ref().and_then(|c| c.agent.as_ref()).and_then(Weak::upgrade).is_some_and(|s| Arc::ptr_eq(&s, scope)) {
            self.setup.revoke_consent();
        }
        // A completed Prepare's Producer is historical proof, not its withdrawn
        // permission. Never call setup.stop() here: that discards this Consent.
        if self.setup.active.as_ref().and_then(|a| a.agent.as_ref()).is_some_and(|e| Arc::ptr_eq(e.scope(), scope)) {
            self.setup.stop();
        }
    }
    pub(crate) fn remote_agent_input(&self, entry: &Arc<r::Entry>) -> Result<Input, BridgeError> {
        let permission = self.setup.agent_permission.as_ref().ok_or_else(no)?;
        if permission.scope.upgrade().is_none_or(|s| !Arc::ptr_eq(&s, entry.scope())) { return Err(no()); }
        Ok(permission.capture.input.clone())
    }
    pub(crate) fn remote_agent_entry(&mut self, command: &w::Command, entry: Option<&Arc<r::Entry>>,
        generation: u32, root: &RegisteredRoot, binding: &str, edit: &SavedEditGuard<'_>, now: Instant,
        variable: Option<crate::asset_session::RemoteSetupVariablePins>) -> Result<(), BridgeError> {
        let Some(entry) = entry else {
            if self.setup.agent_permission.is_some() || matches!(command, w::Command::Apply(_)) && self.setup.consent.as_ref()
                .is_some_and(|c| c.agent.is_some() || !producer_ready(&c.producer)) { return Err(no()); }
            return Ok(());
        };
        entry.current(false).map_err(crate::asset_session::application_service::public_error)?;
        let input = self.remote_agent_input(entry)?;
        if !input.matches_remote(command) { return Err(no()); }
        let review = self.remote_agent_review(input, generation, root, binding, edit, now, Some(entry), variable)?;
        let permission = self.setup.agent_permission.as_ref().ok_or_else(no)?;
        if review.data != entry.scope().review || !Arc::ptr_eq(&review.identity, &entry.scope().identity)
            || review.dispatch.as_ref() != Some(&permission.capture) || !edit.matches(&permission.stamp) { return Err(no()); }
        self.setup.agent_permission.take();
        Ok(())
    }
    pub(crate) fn remote_agent_return(&self, entry: Option<&Arc<r::Entry>>, id: &str,
        kind: w::Kind, selection: &w::Selection, reason: w::Reason, effect: w::Effect) {
        let Some(entry) = entry else { return; };
        // Only the original accept_setup tail calls this after real retirement.
        if self.unknown || reason == w::Reason::CleanupUnknown {
            entry.unknown(p::Reason::CleanupUnknown); return;
        }
        let value = compact(&self.setup.view, id, kind, selection, reason);
        let mapped_effect = match (kind, effect) {
            (w::Kind::Prepare, w::Effect::NotStarted) => p::Effect::None,
            (w::Kind::Apply, w::Effect::NotStarted) => p::Effect::NotSent,
            (w::Kind::Apply, w::Effect::Unknown) => p::Effect::PotentiallyApplied,
            (w::Kind::Apply, w::Effect::ReadbackConfirmed) => p::Effect::SettingsReadbackObserved,
            _ => { entry.unknown(p::Reason::CleanupUnknown); return; }
        };
        match value {
            Ok(snapshot) if snapshot.valid_outcome(entry.scope().review.kind(), snapshot.reason.reason(), mapped_effect) => {
                entry.dispatch_returned(id, snapshot.reason.reason(), mapped_effect,
                    Some(p::dispatch::Snapshot::RemoteSettings(snapshot)));
            }
            _ => entry.unknown(p::Reason::CleanupUnknown),
        }
    }
}
fn compact(view: &w::Status, id: &str, kind: w::Kind, selection: &w::Selection, reason: w::Reason)
    -> Result<p::remote_setup::Snapshot, BridgeError> {
    use p::{dispatch::Hex, remote_setup::{NativeReason, Setting, Snapshot}};
    let setting = match selection {
        w::Selection::ActionsEnabled { .. } => Setting::ActionsEnabled,
        w::Selection::WorkflowTokenPolicy { .. } => Setting::WorkflowTokenPolicy,
        w::Selection::Environment(_) => Setting::EnvironmentProtection,
        w::Selection::Variable(_) => Setting::EnvironmentVariable,
        w::Selection::Secret(_) => return Err(no()),
    };
    let op = view.operation.as_ref().filter(|op| op.id == id && op.kind == kind
        && op.phase == w::Phase::Settled && op.reason == reason).ok_or_else(no)?;
    // Only one fixed enum scalar is converted, never full Status/Prepared/values.
    let reason: NativeReason = serde_json::from_value(serde_json::to_value(reason).map_err(|_| no())?).map_err(|_| no())?;
    let (consent_id, prepared_sha256) = if kind == w::Kind::Prepare && reason == NativeReason::None {
        let c = view.consent.as_ref().filter(|c| &c.prepared.target().selection == selection && c.prepared.valid()).ok_or_else(no)?;
        (Some(Hex::parse(&c.id).ok_or_else(no)?), Some(Hex::parse(&hash(&c.prepared)?).ok_or_else(no)?))
    } else { (None, None) };
    Ok(Snapshot { setting, reason, write_claimed: op.write_claimed, write_acknowledged: op.write_acknowledged,
        consent_id, prepared_sha256, observation_sha256: view.observed.as_ref().map(|v| hash(v)
            .and_then(|h| Hex::parse(&h).ok_or_else(no))).transpose()? })
}
