//! One local-repository permission on the original GitLocal/Inbox owners.
//! Initialize captures the real Document/root/Edit stamp WITHOUT a Git read;
//! only its subsequent original Prepare can establish an absent repository.
use super::*;
use crate::service_git_repository_protocol::{self as repository, shared};

#[path = "service_git_repository_native.rs"]
mod native;
pub(in crate::asset_session) use native::review as agent_git_review;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RepositoryAllow {
    project_id: String,
    expected_document_revision: u32,
    #[serde(deserialize_with = "required_read")]
    read_operation_id: Option<String>,
    action: repository::Action,
    consent_version: String,
}
fn required_read<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
pub(crate) fn decode_repository_empty(bytes: &[u8]) -> Result<(), BridgeError> {
    if bytes.len().saturating_add(96) > 1024 {
        return Err(BridgeError::invalid());
    }
    let _: crate::asset_session::agent_identity::Empty =
        crate::asset_session::agent_identity::decode(bytes)?;
    Ok(())
}
pub(crate) fn decode_repository_allow(bytes: &[u8]) -> Result<RepositoryAllow, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > repository::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    let args = RepositoryAllow::deserialize(&value).map_err(|_| BridgeError::invalid())?;
    if args.project_id.is_empty()
        || args.project_id.len() > 64
        || !(1..u32::MAX).contains(&args.expected_document_revision)
        || args.consent_version != repository::CONSENT
        || args.action.validate().is_err()
        || match args.action {
            repository::Action::Initialize => args.read_operation_id.is_some(),
            _ => !args
                .read_operation_id
                .as_deref()
                .is_some_and(wire::native_id),
        }
    {
        return Err(BridgeError::invalid());
    }
    Ok(args)
}

pub(super) fn successful_read(value: &read::Projection) -> bool {
    matches!(
        value.action.kind,
        read::Kind::Observe | read::Kind::Branches
    ) && value.phase == read::Phase::Settled
        && value.outcome == Some(read::Outcome::Ok)
        && value.reason.is_none()
        && read::validate_result(&value.action, &value.result).is_ok()
}
fn selected(value: &read::Projection, action: &repository::Action) -> bool {
    let Some((revision, refs)) = action.revisions() else {
        return false;
    };
    if !successful_read(value) || value.result["referenceRevision"].as_str() != Some(refs) {
        return false;
    }
    match value.action.kind {
        read::Kind::Branches => {
            !matches!(action, repository::Action::FastForward { .. })
                && value.result["revision"].as_str() == Some(revision)
        }
        read::Kind::Observe => {
            if value.result["observation"]["revision"].as_str() != Some(revision)
                || !value.result["observation"]["restrictions"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
            {
                return false;
            }
            match action {
                repository::Action::FastForward {
                    target_ref,
                    target_oid,
                    ..
                } => {
                    let tracking = &value.result["tracking"];
                    tracking["state"] == "complete"
                        && tracking["localRef"].as_str() == Some(target_ref.as_str())
                        && tracking["head"].as_str() == Some(target_oid.as_str())
                        && tracking["ahead"].as_u64() == Some(0)
                        && tracking["behind"].as_u64().is_some_and(|v| v > 0)
                }
                _ => true,
            }
        }
        _ => false,
    }
}

/// Shared entry rematch: old file families keep their Observe-only contract.
/// A null Init basis is deliberately not a failed or empty Git observation.
pub(super) fn basis_current(
    book: &Book,
    state: &DocumentState,
    scope: &requests::NativeScope,
    original: &Arc<Observation>,
) -> bool {
    if matches!(&scope.selection, shared::Selected::Repository(s) if matches!(s.action,repository::Action::Initialize))
    {
        return scope.read_operation_id.is_none();
    }
    let Some(id) = scope.read_operation_id.as_deref() else {
        return false;
    };
    if book
        .observed
        .as_ref()
        .is_none_or(|o| !Arc::ptr_eq(&o.original, original) || o.operation_id != id)
    {
        return false;
    }
    let Some(git_read::Entry::Finished(value)) = &state.git_read else {
        return false;
    };
    if value.operation_id != id {
        return false;
    }
    match &scope.selection {
        shared::Selected::Files(_) => successful_observe(value),
        shared::Selected::Repository(s) => selected(value, &s.action),
    }
}

impl DocumentBinding {
    pub(crate) fn agent_git_repository_access(
        &self,
        window: &str,
    ) -> Result<repository::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.git_index_service()? {
            Some(s) => s.git_index_requests().repository_access().map_err(public),
            None => Ok(repository::Access::empty()),
        }
    }
    pub(crate) fn allow_agent_git_repository(
        &self,
        window: &str,
        args: RepositoryAllow,
    ) -> Result<repository::Access, BridgeError> {
        if window != MAIN || args.consent_version != repository::CONSENT {
            return Err(BridgeError::invalid());
        }
        let selection = repository::Selection::new(args.action).map_err(public)?;
        let (original, revoke_epoch) = {
            let mut state = self.lock();
            git_read::reconcile(&mut state);
            git_local::reconcile(&self.inner, &mut state);
            self.git_local_new_gate(&state)?;
            if state.git_local_review.is_some() || state.revision != args.expected_document_revision
            {
                return Err(public(Error::Conflict));
            }
            let (generation, root) = self.git_index_registered(&mut state, &args.project_id)?;
            let epoch = self.inner.android_registration_control.epoch()?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let book = self
                .inner
                .agent_git_index
                .book
                .lock()
                .map_err(|_| public(Error::StateUnknown))?;
            if book.revoke_epoch == u64::MAX {
                return Err(public(Error::StateUnknown));
            }
            let original = match &selection.action {
                repository::Action::Initialize => {
                    if args.read_operation_id.is_some() {
                        return Err(BridgeError::invalid());
                    }
                    // Comparison witness only. No .git query/tool/project IO at Allow.
                    let (device, inode) = root.identity.posix()
                        .map_err(|_| public(Error::Unavailable))?.service_identity();
                    Arc::new(Observation {
                        root: root.clone(),
                        native: NativeProject {
                            runtime_id: args.project_id.clone(),
                            canonical_root: root.path.clone(),
                            device,
                            inode,
                            registration_generation: generation,
                            document_identity: self.inner.session_identity.clone(),
                            input_revision: epoch,
                        },
                        stamp: edit.stamp()?,
                        document_revision: state.revision,
                    })
                }
                action => {
                    let observed = book
                        .observed
                        .as_ref()
                        .ok_or_else(|| public(Error::Unavailable))?;
                    let Some(git_read::Entry::Finished(value)) = &state.git_read else {
                        return Err(public(Error::Conflict));
                    };
                    if args.read_operation_id.as_deref() != Some(observed.operation_id.as_str())
                        || value.operation_id != observed.operation_id
                        || observed.original.native.runtime_id != args.project_id
                        || !selected(value, action)
                    {
                        return Err(public(Error::Conflict));
                    }
                    observed.original.clone()
                }
            };
            self.git_index_observation_current(&state, &original, &root, generation, epoch, &edit)?;
            (original, book.revoke_epoch)
        };
        // SAME Host and authenticated read grant, entirely outside Doc/Edit.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original.native)
            .map_err(public)?;
        let point = service
            .git_index_point(&original.native.runtime_id)
            .map_err(public)?;
        if point.root != original.root.path
            || (point.device, point.inode) != (original.native.device, original.native.inode)
        {
            return Err(public(Error::Conflict));
        }
        let scope = Arc::new(requests::NativeScope {
            project_id: point.project_id,
            runtime_id: original.native.runtime_id.clone(),
            root: original.root.path.clone(),
            device: point.device,
            inode: point.inode,
            registration: original.native.registration_generation,
            document_revision: original.document_revision,
            input_revision: original.native.input_revision,
            read_operation_id: args.read_operation_id,
            document: Arc::downgrade(&self.inner.session_identity),
            selection: selection.into(),
            commit: None,
            changes: self.inner.changes.clone(),
        });
        let mut state = self.lock();
        self.git_local_new_gate(&state)?;
        if state.git_local_review.is_some() {
            return Err(public(Error::Conflict));
        }
        let (generation, root) =
            self.git_index_registered(&mut state, &original.native.runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.git_index_observation_current(
            &state,
            &original,
            &root,
            generation,
            self.inner.android_registration_control.epoch()?,
            &edit,
        )?;
        let mut book = self
            .inner
            .agent_git_index
            .book
            .lock()
            .map_err(|_| public(Error::StateUnknown))?;
        if book.revoke_epoch != revoke_epoch || !basis_current(&book, &state, &scope, &original) {
            return Err(public(Error::Conflict));
        }
        if let Some(old) = self.inner.agent_git_index.service.get() {
            if old.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_git_index
                .service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        let access = service
            .git_index_requests()
            .allow_repository(scope.clone())
            .map_err(public)?;
        book.grant = Some(Arc::new(Grant {
            scope,
            observation: original,
        }));
        Ok(access)
    }
    pub(crate) fn revoke_agent_git_repository(
        &self,
        window: &str,
    ) -> Result<repository::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let advance = (|| {
            let mut book = self
                .inner
                .agent_git_index
                .book
                .lock()
                .map_err(|_| public(Error::StateUnknown))?;
            book.revoke_epoch = book
                .revoke_epoch
                .checked_add(1)
                .ok_or_else(|| public(Error::StateUnknown))?;
            Ok(())
        })();
        let stop = match self.git_index_service() {
            Ok(Some(s)) => s.git_index_requests().revoke_repository().map_err(public),
            Ok(None) => Ok(repository::Access::empty()),
            Err(e) => Err(e),
        };
        advance.and(stop)
    }
}

pub(super) fn action(scope: &requests::NativeScope) -> Result<local::Action, BridgeError> {
    match &scope.selection {
        shared::Selected::Files(_) => commit::action(scope),
        shared::Selected::Repository(selected) => native::action(&selected.action),
    }
}

#[cfg(test)]
#[path = "service_git_repository_document_tests.rs"]
mod tests;
