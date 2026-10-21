//! Read-only application-service integration through the existing document and
//! passive query owner. A shared snapshot is never a release/build permission.
use super::*;
use crate::{
    application_service::ReadAccessStatus,
    application_service_host::{AllowTicket, NativeProject, SnapshotTicket},
    edit_owner::SavedEditStamp,
    service_protocol::Error as ServiceError,
};
use std::path::{Path, PathBuf};

pub(crate) fn public_error(error: ServiceError) -> BridgeError {
    let code = match error {
        ServiceError::InvalidRequest => "cli_access_invalid_request",
        ServiceError::Unavailable | ServiceError::UnsupportedPlatform => "cli_access_unavailable",
        ServiceError::AccessDenied | ServiceError::Expired => "cli_access_denied",
        ServiceError::Busy => "cli_access_busy",
        ServiceError::Conflict => "cli_access_changed",
        ServiceError::RecoveryRequired => "cli_access_recovery_required",
        ServiceError::StateUnknown => "cli_access_unknown",
    };
    BridgeError::new(code, error.message())
}

pub(crate) fn empty_request(value: &Value) -> Result<(), BridgeError> {
    if value.as_object().is_some_and(|object| object.is_empty()) { Ok(()) }
    else { Err(BridgeError::invalid()) }
}

/// Only this MAIN observation exposes the original permission epoch. The
/// shared service, installed CLI and headless status DTO remain unchanged.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainReadAccessStatus {
    #[serde(flatten)]
    access: ReadAccessStatus,
    #[serde(serialize_with = "serialize_permission_revision")]
    pub(crate) permission_revision: u64,
}
fn serialize_permission_revision<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

pub(crate) fn allow_request(value: &Value) -> Result<(&str, u64), BridgeError> {
    let object = value.as_object().filter(|object| object.len() == 2).ok_or_else(BridgeError::invalid)?;
    let id = object.get("projectId").and_then(Value::as_str).filter(|id| crate::protocol::valid_id(id))
        .ok_or_else(BridgeError::invalid)?;
    let revision = object.get("expectedPermissionRevision").and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0')))
        .and_then(|s| s.parse::<u64>().ok()).ok_or_else(BridgeError::invalid)?;
    Ok((id, revision))
}

struct SharedObservation {
    original: NativeProject,
    stamp: SavedEditStamp,
    ticket: SnapshotTicket,
}

/// The original query still retains/settles all its work if this observer is
/// dropped. Dropping an observer simply cannot publish a new shared snapshot.
pub(crate) struct ProjectQuery {
    query: crate::supervisor::PassiveQuery,
    document: DocumentBinding,
    shared: Option<SharedObservation>,
}
impl ProjectQuery {
    pub(crate) async fn wait(self) -> Result<Value, BridgeError> {
        let result = self.query.wait().await;
        if let Some(shared) = self.shared {
            self.document.finish_shared_observation(shared, result.as_ref().ok());
        }
        // Shared-state publication failure does not rewrite the independent
        // original core observation. Its own host retains the failure/revokes.
        result
    }
}

impl DocumentBinding {
    pub(super) fn service_document_gate(&self, state: &DocumentState) -> Result<(), BridgeError> {
        passive_document_gate(state)?;
        if !state.lifetime.original_bound() || state.lost_observed {
            return Err(public_error(ServiceError::Unavailable));
        }
        Ok(())
    }

    /// Caller holds the real document mutex. These facts come from its native
    /// project registry, original document Arc and original input control book.
    pub(super) fn service_project_locked(&self, state: &DocumentState, id: &str) -> Result<NativeProject, BridgeError> {
        self.service_document_gate(state)?;
        let (registration_generation, root) = self.inner.bridge.native_project(id)
            .map_err(|_| public_error(ServiceError::Conflict))?;
        let (device, inode) = root.identity.posix().map_err(|_| public_error(ServiceError::UnsupportedPlatform))?
            .service_identity();
        Ok(NativeProject {
            runtime_id: id.to_owned(), canonical_root: root.path, device, inode,
            registration_generation, document_identity: self.inner.session_identity.clone(),
            input_revision: self.inner.android_registration_control.epoch()?,
        })
    }

    pub(crate) fn service_project_query(&self, bridge: &DesktopBridge, id: &str) -> Result<ProjectQuery, BridgeError> {
        let state = self.lock();
        self.passive_query_gate_locked(&state, bridge)?;
        let root = bridge.project_root(id)?;
        // Ordinary passive reads retain their original availability. Merely
        // enabling this observer cannot turn a usable core read into a refusal.
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).ok();
        let shared = (|| {
            let original = self.service_project_locked(&state, id).ok()?;
            if original.canonical_root != root { return None; }
            let stamp = edit.as_ref()?.stamp().ok()?;
            let ticket = bridge.application_service.snapshot_ticket(&original).ok()??;
            Some(SharedObservation { original, stamp, ticket })
        })();
        let query = bridge.supervisor.start_passive(crate::protocol::Method::ProjectSnapshot,
            serde_json::json!({"root": root}))?;
        // Same original edit guard spans admission, not just an unlocked stamp.
        drop(edit);
        Ok(ProjectQuery { query, document: self.clone(), shared })
    }

    fn finish_shared_observation(&self, shared: SharedObservation, snapshot: Option<&Value>) {
        let state = self.lock();
        let host = &self.inner.bridge.application_service;
        let publish = (|| {
            let current = self.service_project_locked(&state, &shared.original.runtime_id)?;
            let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            if !edit.matches(&shared.stamp)
                || !self.inner.android_registration_control.matches_epoch(shared.original.input_revision) {
                return Err(public_error(ServiceError::Conflict));
            }
            let snapshot = snapshot.ok_or_else(|| public_error(ServiceError::Unavailable))?;
            host.publish_snapshot(shared.ticket, &current, snapshot).map_err(public_error)
        })();
        if publish.is_err() {
            // A failed/stale original read cannot refresh old saved data. This
            // call preserves its own error/fence if storage is unavailable.
            let _ = host.invalidate_native(&shared.original.runtime_id);
        }
    }

    pub(super) fn service_allow_current_locked(&self, state: &DocumentState, original: &NativeProject,
        stamp: &SavedEditStamp) -> Result<NativeProject, BridgeError> {
        let current = self.service_project_locked(state, &original.runtime_id)?;
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(stamp) || current.canonical_root != original.canonical_root
            || current.device != original.device || current.inode != original.inode
            || current.registration_generation != original.registration_generation
            || !Arc::ptr_eq(&current.document_identity, &original.document_identity)
            || current.input_revision != original.input_revision {
            return Err(public_error(ServiceError::Conflict));
        }
        Ok(current)
    }

    pub(crate) fn application_read_status(&self) -> Result<MainReadAccessStatus, BridgeError> {
        let state = self.lock();
        self.service_document_gate(&state)?;
        let (access, permission_revision) = self.inner.bridge.application_service.status_for_allow().map_err(public_error)?;
        Ok(MainReadAccessStatus { access, permission_revision })
    }

    pub(crate) fn revoke_application_read(&self) -> Result<ReadAccessStatus, BridgeError> {
        // Revocation is independent of the selected project and ordinary work.
        // It must remain available while an earlier Allow is still awaiting IO.
        self.inner.bridge.application_service.revoke().map_err(public_error)
    }

    pub(crate) async fn allow_application_read(&self, id: &str, expected_permission_revision: u64,
        app_data: &Path) -> Result<ReadAccessStatus, BridgeError> {
        let host = &self.inner.bridge.application_service;
        let (original, stamp, ticket) = {
            let state = self.lock();
            self.passive_query_gate_locked(&state, &self.inner.bridge)?;
            let original = self.service_project_locked(&state, id)?;
            let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let stamp = edit.stamp()?;
            let roster = self.inner.bridge.native_roster().map_err(|_| public_error(ServiceError::Conflict))?;
            let ticket = host.begin_allow(original.clone(), expected_permission_revision,
                app_data, &roster.roots).map_err(public_error)?;
            (original, stamp, ticket)
        };
        // A failed old observer must not invalidate a newer caller's ticket.
        // It cannot grant without its own ticket; explicit Revoke/new Allow or
        // the native expiry retires an abandoned pending request.
        self.complete_application_allow(original, stamp, ticket, app_data).await
    }

    async fn complete_application_allow(&self, original: NativeProject, stamp: SavedEditStamp,
        ticket: AllowTicket, app_data: &Path) -> Result<ReadAccessStatus, BridgeError> {
        let host = &self.inner.bridge.application_service;
        host.prepare(&ticket, app_data).await.map_err(public_error)?;
        let query = {
            let state = self.lock();
            self.passive_query_gate_locked(&state, &self.inner.bridge)?;
            self.service_allow_current_locked(&state, &original, &stamp)?;
            // Retain the SAME edit registry lock through actual query claim.
            let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            if !edit.matches(&stamp) { return Err(public_error(ServiceError::Conflict)); }
            let query = self.inner.bridge.supervisor.start_passive(crate::protocol::Method::ProjectSnapshot,
                serde_json::json!({"root": original.canonical_root}))?;
            drop(edit);
            query
        };
        let snapshot = query.wait().await?;
        let state = self.lock();
        let current = self.service_allow_current_locked(&state, &original, &stamp)?;
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&stamp) { return Err(public_error(ServiceError::Conflict)); }
        let result = host.finish_allow(ticket, &current, &snapshot).map_err(public_error);
        drop(edit);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_access_requests_cannot_name_paths_accounts_or_actions() {
        assert!(empty_request(&serde_json::json!({})).is_ok());
        let valid = serde_json::json!({"projectId":"project-1","expectedPermissionRevision":"0"});
        assert_eq!(allow_request(&valid).unwrap(), ("project-1", 0));
        let last = serde_json::json!({"projectId":"project-1","expectedPermissionRevision":u64::MAX.to_string()});
        assert_eq!(allow_request(&last).unwrap(), ("project-1", u64::MAX));
        for value in [Value::Null, serde_json::json!([]), serde_json::json!({"root":"/tmp"}),
            serde_json::json!({"projectId":"project-1","action":"publish"}),
            serde_json::json!({"projectId":"project-1"}),
            serde_json::json!({"projectId":"project-1","expectedPermissionRevision":"0","root":"/tmp"}),
            serde_json::json!({"projectId":"../../other"}), serde_json::json!({"projectId":1})] {
            assert!(empty_request(&value).is_err());
            assert!(allow_request(&value).is_err());
        }
        for revision in [serde_json::json!(0), Value::Null, serde_json::json!(""), serde_json::json!("00"),
            serde_json::json!("+1"), serde_json::json!("-1"), serde_json::json!("1\n"),
            serde_json::json!("18446744073709551616")] {
            assert!(allow_request(&serde_json::json!({"projectId":"project-1","expectedPermissionRevision":revision})).is_err());
        }
    }
    #[test]
    fn main_read_access_revision_is_lossless_without_changing_shared_status() {
        let access = ReadAccessStatus { enabled: false, remaining_ms: 0, project_ids: Vec::new() };
        let base = serde_json::to_value(&access).unwrap();
        assert_eq!(base, serde_json::json!({"enabled":false,"remainingMs":0,"projectIds":[]}));
        let main = MainReadAccessStatus { access, permission_revision: 9_007_199_254_740_993 };
        let value = serde_json::to_value(main).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["permissionRevision"], "9007199254740993");
        for field in ["enabled", "remainingMs", "projectIds"] { assert_eq!(value[field], base[field]); }
    }
    #[test]
    fn dormant_document_cannot_grant_or_report_access_as_available() {
        let bridge = Arc::new(DesktopBridge::new(PathBuf::from("/unopened-cli-document-fixture")));
        let document = DocumentBinding::new(bridge.clone());
        assert!(document.application_read_status().is_err());
        assert!(!document.revoke_application_read().unwrap().enabled);
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
}
