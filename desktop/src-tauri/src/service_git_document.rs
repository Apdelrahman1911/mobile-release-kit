//! One named agent permission on the SAME native Git read/local-write owners.
//! All inbox callbacks are memory-only. Host/service IO is outside Doc/Edit.
use super::*;
use crate::{
    application_service::ApplicationService, application_service_host::NativeProject,
    edit_owner::SavedEditStamp, git_local_protocol as local, git_read_protocol as read,
    service_git_protocol as wire, service_git_requests as requests, service_protocol::Error,
};
use serde::Deserialize;
use std::{path::Path, sync::OnceLock};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    expected_document_revision: u32,
    read_operation_id: String,
    action: wire::Action,
    paths: Vec<String>,
    consent_version: String,
}
pub(crate) fn decode_allow(bytes: &[u8]) -> Result<Allow, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > local::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    let args = Allow::deserialize(&value).map_err(|_| BridgeError::invalid())?;
    if args.project_id.is_empty()
        || args.project_id.len() > 64
        || !wire::native_id(&args.read_operation_id)
        || !(1..u32::MAX).contains(&args.expected_document_revision)
        || args.paths.is_empty()
        || args.paths.len() > wire::PATH_LIMIT
        || args.paths.iter().any(|p| !wire::relative(p))
        || args.paths.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(BridgeError::invalid());
    }
    Ok(args)
}
/// Captured at actual Observe admission, retained through its original Gate.
/// An old public projection alone cannot reconstruct this comparison witness.
pub(super) struct Observation {
    root: asset_source::RegisteredRoot,
    native: NativeProject,
    stamp: SavedEditStamp,
    document_revision: u32,
}
struct Observed {
    original: Arc<Observation>,
    operation_id: String,
}
struct Grant {
    scope: Arc<requests::NativeScope>,
    observation: Arc<Observation>,
}
#[derive(Default)]
struct Book {
    observed: Option<Observed>,
    grant: Option<Arc<Grant>>,
    revoke_epoch: u64,
}
#[derive(Default)]
pub(super) struct NativeState {
    book: Mutex<Book>,
    service: OnceLock<Weak<ApplicationService>>,
}
// Two original Observe/Grant comparison witnesses plus temporary rematch/GUI
// decode, not a new native source owner. Paths themselves are charged once in
// the inbox; the actual native Git action/review charges remain unchanged.
pub(super) const fn document_backing() -> usize {
    4 * (8192 + std::mem::size_of::<Observation>())
        + std::mem::size_of::<NativeState>()
        + std::mem::size_of::<Grant>()
        + 2 * local::REQUEST_LIMIT
}
fn public(error: Error) -> BridgeError {
    application_service::public_error(error)
}

/// Optional write-consent provenance. Failure only makes a later Allow
/// unavailable; ordinary read admission and its result are unchanged.
pub(super) fn observe_admission(
    document: &Arc<Inner>,
    state: &DocumentState,
    project: &str,
    generation: u32,
    root: &asset_source::RegisteredRoot,
    action: &read::Action,
) -> Option<Arc<Observation>> {
    if action.kind != read::Kind::Observe {
        return None;
    }
    let epoch = document.android_registration_control.epoch().ok()?;
    let edit = document
        .bridge
        .edits
        .saved_registration_guard(&document.session_identity)
        .ok()?;
    let (device, inode) = root.identity.posix().ok()?.service_identity();
    Some(Arc::new(Observation {
        root: root.clone(),
        native: NativeProject {
            runtime_id: project.into(),
            canonical_root: root.path.clone(),
            device,
            inode,
            registration_generation: generation,
            document_identity: document.session_identity.clone(),
            input_revision: epoch,
        },
        stamp: edit.stamp().ok()?,
        document_revision: state.revision,
    }))
}
fn successful_observe(value: &read::Projection) -> bool {
    value.action.kind == read::Kind::Observe
        && value.phase == read::Phase::Settled
        && value.outcome == Some(read::Outcome::Ok)
        && value.reason.is_none()
        && value
            .result
            .get("observation")
            .and_then(|o| o.get("revision"))
            .and_then(Value::as_str)
            .is_some_and(wire::digest)
        && read::validate_result(&value.action, &value.result).is_ok()
}
/// Only GitRead::reconcile calls this, after its original receipt joins. It
/// does not lock a Document, create a task or use a child event as settlement.
pub(super) fn observe_returned(
    document: &Arc<Inner>,
    original: Option<&Arc<Observation>>,
    value: &read::Projection,
) {
    let Ok(mut book) = document.agent_git_index.book.lock() else {
        return;
    };
    book.observed = original
        .filter(|o| {
            successful_observe(value)
                && o.native.runtime_id == value.context.project_id
                && o.native.registration_generation == value.context.generation
                && value.context.revision == format!("document-{}", o.document_revision)
        })
        .map(|original| Observed {
            original: original.clone(),
            operation_id: value.operation_id.clone(),
        });
}
fn selection(
    value: &read::Projection,
    action: wire::Action,
    paths: Vec<String>,
) -> Result<wire::Selection, BridgeError> {
    if !successful_observe(value)
        || !value.result["observation"]
            .get("restrictions")
            .and_then(Value::as_array)
            .is_some_and(|v| v.is_empty())
    {
        return Err(public(Error::Conflict));
    }
    let selected = wire::Selection::new(
        action,
        value.result["observation"]["revision"]
            .as_str()
            .ok_or_else(|| public(Error::Conflict))?
            .into(),
        paths,
    )
    .map_err(public)?;
    let changes = value.result["observation"]
        .get("changes")
        .and_then(Value::as_array)
        .ok_or_else(|| public(Error::Conflict))?;
    for path in &selected.paths {
        let mut rows = changes
            .iter()
            .filter(|row| row.get("path").and_then(Value::as_str) == Some(path));
        let row = rows.next().ok_or_else(|| public(Error::Conflict))?;
        if rows.next().is_some() || row.get("conflict").and_then(Value::as_bool) != Some(false) {
            return Err(public(Error::Conflict));
        }
        let mark = row
            .get(match action {
                wire::Action::Stage => "worktree",
                wire::Action::Unstage => "index",
            })
            .and_then(Value::as_str);
        if !mark.is_some_and(|v| v.len() == 1 && v != " " && v != ".") {
            return Err(public(Error::Conflict));
        }
    }
    Ok(selected)
}
impl DocumentBinding {
    fn git_index_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_git_index
            .service
            .get()
            .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn git_index_observation_current(
        &self,
        state: &DocumentState,
        original: &Observation,
        root: &asset_source::RegisteredRoot,
        generation: u32,
        epoch: u64,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        if state.revision != original.document_revision
            || root != &original.root
            || generation != original.native.registration_generation
            || epoch != original.native.input_revision
            || !edit.matches(&original.stamp)
            || !Arc::ptr_eq(
                &self.inner.session_identity,
                &original.native.document_identity,
            )
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    fn git_index_registered(
        &self,
        state: &mut DocumentState,
        id: &str,
    ) -> Result<(u32, asset_source::RegisteredRoot), BridgeError> {
        self.registry_result(state, self.inner.bridge.native_project(id), None)
            .map_err(|e| {
                public(if e.reason == Reason::CleanupUnknown {
                    Error::StateUnknown
                } else {
                    Error::Conflict
                })
            })
    }
    pub(crate) fn agent_git_index_access(&self, window: &str) -> Result<wire::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.git_index_service()? {
            Some(s) => s.git_index_requests().access().map_err(public),
            None => Ok(wire::Access::empty()),
        }
    }
    pub(crate) fn allow_agent_git_index(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<wire::Access, BridgeError> {
        if window != MAIN || args.consent_version != wire::CONSENT {
            return Err(BridgeError::invalid());
        }
        let (original, selected, revoke_epoch) = {
            let mut state = self.lock();
            git_read::reconcile(&mut state);
            git_local::reconcile(&self.inner, &mut state);
            self.git_local_new_gate(&state)?;
            if state.git_local_review.is_some() || state.revision != args.expected_document_revision
            {
                return Err(public(Error::Conflict));
            }
            let (generation, root) = self.git_index_registered(&mut state, &args.project_id)?;
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
            let observed = book
                .observed
                .as_ref()
                .ok_or_else(|| public(Error::Unavailable))?;
            let Some(git_read::Entry::Finished(value)) = &state.git_read else {
                return Err(public(Error::Conflict));
            };
            if observed.operation_id != args.read_operation_id
                || value.operation_id != observed.operation_id
                || observed.original.native.runtime_id != args.project_id
                || book.revoke_epoch == u64::MAX
            {
                return Err(public(Error::Conflict));
            }
            self.git_index_observation_current(
                &state,
                &observed.original,
                &root,
                generation,
                self.inner.android_registration_control.epoch()?,
                &edit,
            )?;
            (
                observed.original.clone(),
                selection(value, args.action, args.paths)?,
                book.revoke_epoch,
            )
        };
        // These existing calls can do Store IO. No Doc/Edit/native-book guard.
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
            selection: selected,
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
        if book.revoke_epoch != revoke_epoch
            || book.observed.as_ref().is_none_or(|o| {
                !Arc::ptr_eq(&o.original, &original) || o.operation_id != scope.read_operation_id
            })
            || !matches!(&state.git_read,Some(git_read::Entry::Finished(v)) if v.operation_id==scope.read_operation_id&&successful_observe(v))
        {
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
            .allow(scope.clone())
            .map_err(public)?;
        book.grant = Some(Arc::new(Grant {
            scope,
            observation: original,
        }));
        Ok(access)
    }
    pub(crate) fn revoke_agent_git_index(&self, window: &str) -> Result<wire::Access, BridgeError> {
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
            Ok(Some(s)) => s.git_index_requests().revoke().map_err(public),
            Ok(None) => Ok(wire::Access::empty()),
            Err(e) => Err(e),
        };
        advance.and(stop)
    }
    /// Shared Prepare/Apply boundary, inside the original Doc/Edit guards.
    /// The caller supplies the real publisher epoch for Apply (not epoch()).
    pub(super) fn agent_git_index_admission(
        &self,
        state: &DocumentState,
        link: &requests::NativeLink,
        phase: requests::Phase,
        root: &asset_source::RegisteredRoot,
        generation: u32,
        epoch: u64,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        action: &local::Action,
    ) -> Result<(), BridgeError> {
        let book = self
            .inner
            .agent_git_index
            .book
            .lock()
            .map_err(|_| public(Error::StateUnknown))?;
        let grant = book.grant.as_ref().ok_or_else(|| public(Error::Conflict))?;
        if link.phase() != phase
            || !Arc::ptr_eq(link.scope(), &grant.scope)
            || link.stopped()
            || !same_action(action, &grant.scope.selection)
        {
            return Err(public(Error::Conflict));
        }
        self.git_index_observation_current(
            state,
            &grant.observation,
            root,
            generation,
            epoch,
            edit,
        )?;
        if phase == requests::Phase::Prepare
            && (book
                .observed
                .as_ref()
                .is_none_or(|o| !Arc::ptr_eq(&o.original, &grant.observation))
                || !matches!(&state.git_read,Some(git_read::Entry::Finished(v)) if v.operation_id==grant.scope.read_operation_id&&successful_observe(v)))
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    fn admit_git_index(
        &self,
        service: &Arc<ApplicationService>,
        claim: &mut requests::Claim,
        app_data: &Path,
    ) -> Result<(), BridgeError> {
        let scope = claim.entry().scope().map_err(public)?;
        let original = {
            let _state = self.lock();
            let book = self
                .inner
                .agent_git_index
                .book
                .lock()
                .map_err(|_| public(Error::StateUnknown))?;
            book.grant
                .as_ref()
                .filter(|g| Arc::ptr_eq(&g.scope, &scope))
                .map(|g| g.observation.clone())
                .ok_or_else(|| public(Error::Conflict))?
        };
        let current = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original.native)
            .map_err(public)?;
        let point = service.git_index_point(&scope.runtime_id).map_err(public)?;
        if !Arc::ptr_eq(service, &current)
            || point.project_id != scope.project_id
            || point.root != scope.root
            || (point.device, point.inode) != (scope.device, scope.inode)
        {
            return Err(public(Error::Conflict));
        }
        let link = claim.link().map_err(public)?;
        let result = match claim.phase() {
            requests::Phase::Prepare => self.git_local_prepare_original(
                local::Prepare {
                    project_id: scope.runtime_id.clone(),
                    expected_document_revision: scope.document_revision,
                    action: native_action(&scope.selection)?,
                },
                Some(link),
            ),
            requests::Phase::Apply => {
                let start = claim.start().map_err(public)?;
                self.git_local_apply_original(
                    local::Apply {
                        project_id: scope.runtime_id.clone(),
                        expected_document_revision: scope.document_revision,
                        review_id: start.review_id,
                    },
                    app_data,
                    Some(link),
                )
            }
        }?;
        if !matches!(result.admission, read::Admission::Started) {
            return Err(public(match result.reason {
                Some(read::StartRefusal::Busy) => Error::Busy,
                Some(read::StartRefusal::Unavailable) => Error::Unavailable,
                _ => Error::Conflict,
            }));
        }
        Ok(())
    }
    /// SAME retained relay. No new worker, timer, reader, service or journal.
    pub(crate) fn service_git_index_tick(&self, app_data: &Path) {
        let Ok(Some(service)) = self.git_index_service() else {
            return;
        };
        {
            let mut state = self.lock();
            git_local::agent_tick(&self.inner, &mut state); // Exact original STOP/review retirement first.
            if !git_local::agent_running(&state) {
                let current = (|| {
                    let grant = {
                        let book = self
                            .inner
                            .agent_git_index
                            .book
                            .lock()
                            .map_err(|_| public(Error::StateUnknown))?;
                        book.grant.clone()
                    };
                    let Some(grant) = grant else {
                        return Ok(());
                    };
                    let (generation, root) = self
                        .git_index_registered(&mut state, &grant.observation.native.runtime_id)?;
                    let edit = self
                        .inner
                        .bridge
                        .edits
                        .saved_registration_guard(&self.inner.session_identity)?;
                    self.git_index_observation_current(
                        &state,
                        &grant.observation,
                        &root,
                        generation,
                        self.inner.android_registration_control.epoch()?,
                        &edit,
                    )
                })();
                if current.is_err() {
                    let _ = service.git_index_requests().revoke();
                }
            }
        }
        match service.git_index_requests().claim() {
            Ok(Some(mut claim)) => {
                let result = self
                    .admit_git_index(&service, &mut claim, app_data)
                    .map_err(|e| {
                        if e.code == "cleanup_unknown" {
                            Error::StateUnknown
                        } else if e.code == "busy" {
                            Error::Busy
                        } else if e.code == "runtime_unavailable" {
                            Error::Unavailable
                        } else {
                            Error::Conflict
                        }
                    });
                claim.returned(result);
            }
            Ok(None) => {}
            Err(_) => {
                let _ = service.git_index_requests().revoke();
            }
        }
        let _ = flush(&service);
    }
    pub(crate) fn git_index_relay_lost(&self) {
        if let Ok(Some(s)) = self.git_index_service() {
            let _ = s.git_index_requests().revoke();
        }
    }
    pub(crate) fn drain_git_index_for_exit(&self) {
        if let Ok(Some(s)) = self.git_index_service() {
            s.git_index_requests().close();
            {
                let mut state = self.lock();
                git_local::agent_tick(&self.inner, &mut state);
            }
            let _ = flush(&s);
        }
    }
}
fn same_action(action: &local::Action, selection: &wire::Selection) -> bool {
    // The original action validator enforces absent private commit fields for
    // Stage/Unstage; this child needs no access to those fields.
    action.valid()
        && matches!(action,local::Action::Files(v) if v.kind==match selection.summary.action {wire::Action::Stage=>local::Kind::Stage,wire::Action::Unstage=>local::Kind::Unstage}
            && v.expected_revision==selection.summary.repository_revision && v.paths==selection.paths)
}
fn native_action(selection: &wire::Selection) -> Result<local::Action, BridgeError> {
    local::Action::index(
        match selection.summary.action {
            wire::Action::Stage => local::Kind::Stage,
            wire::Action::Unstage => local::Kind::Unstage,
        },
        selection.summary.repository_revision.clone(),
        selection.paths.clone(),
    )
}
fn flush(service: &ApplicationService) -> Result<(), Error> {
    struct Final<'a>(&'a ApplicationService, bool);
    impl Drop for Final<'_> {
        fn drop(&mut self) {
            if !self.1 {
                self.0.fence_native_history();
            }
        }
    }
    let mut finality = Final(service, false);
    let mut first = None;
    for entry in service.git_index_requests().entries()? {
        let data = match entry.claim_history() {
            Ok(v) => v,
            Err(e) => {
                first.get_or_insert(e);
                continue;
            }
        };
        let Some((new, revision, state, settlement)) = data else {
            continue;
        };
        let action = match entry.status()?.selection.action {
            wire::Action::Stage => crate::service_protocol::Action::GitStage,
            wire::Action::Unstage => crate::service_protocol::Action::GitUnstage,
        };
        let id = entry.input().origin.request_id.clone();
        let result = if new {
            service.begin_operation(entry.runtime_id(), id, action, state, settlement)
        } else {
            service.publish_operation(entry.runtime_id(), id, action, state, settlement)
        };
        if let Err(e) = entry.history_returned(revision, result) {
            first.get_or_insert(e);
        }
    }
    if let Some(e) = first {
        Err(e)
    } else {
        finality.1 = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_git_document_tests.rs"]
mod tests;
