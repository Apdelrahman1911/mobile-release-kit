//! One Desktop-selected Remote permission on the SAME finite Git inbox.
//! Native Observe + exact Connection Pins are retained before off-Doc service
//! checks, then rematched under the second Doc cut. No CLI selects a target.
use super::*;
use crate::service_git_remote_protocol as remote;
use crate::service_git_repository_protocol::shared;
#[path = "service_git_remote_native.rs"]
mod native;
pub(super) use native::Approval;
pub(in crate::asset_session) use native::{outcome, review};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RemoteAllow {
    project_id: String,
    expected_document_revision: u32,
    expected_permission_revision: PermissionRevision,
    read_operation_id: String,
    action: remote::Action,
    consent_version: String,
}
pub(crate) fn decode_remote_allow(bytes: &[u8]) -> Result<RemoteAllow, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > remote::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    let args = RemoteAllow::deserialize(&value).map_err(|_| BridgeError::invalid())?;
    if !crate::protocol::valid_id(&args.project_id)
        || !(1..u32::MAX).contains(&args.expected_document_revision)
        || !wire::native_id(&args.read_operation_id)
        || args.action.validate().is_err()
        || args.consent_version != args.action.kind().consent()
    {
        return Err(BridgeError::invalid());
    }
    Ok(args)
}
/// Only eligibility DATA, always paired with Book.observed's genuine captured
/// original. An empty/foreign read or a cached tracking row alone cannot Allow.
pub(super) fn selected(value: &read::Projection, action: &remote::Action) -> bool {
    if !successful_observe(value) || action.validate().is_err() {
        return false;
    }
    let (revision, refs) = action.revisions();
    let o = &value.result["observation"];
    if o["revision"].as_str() != Some(revision)
        || value.result["referenceRevision"].as_str() != Some(refs)
        || !o["restrictions"].as_array().is_some_and(Vec::is_empty)
    {
        return false;
    }
    let observed_remote = |remote: &str| {
        o["remotes"]
            .as_array()
            .is_some_and(|v| v.iter().any(|r| r.as_str() == Some(remote)))
    };
    match action {
        remote::Action::Fetch { remote, .. } => observed_remote(remote),
        remote::Action::Push {
            remote,
            local_ref,
            remote_ref,
            old_oid,
            new_oid,
            ..
        } => {
            let t = &value.result["tracking"];
            observed_remote(remote)
                && o["unborn"] == false
                && o["detached"] == false
                && o["branch"].as_str() == Some(local_ref.as_str())
                && o["head"].as_str() == Some(new_oid.as_str())
                && t["state"] == "complete"
                && t["remote"].as_str() == Some(remote.as_str())
                && t["mergeRef"].as_str() == Some(remote_ref.as_str())
                && t["localRef"].as_str()
                    == Some(format!("refs/remotes/{remote}/{}", &remote_ref[11..]).as_str())
                && t["head"].as_str() == Some(old_oid.as_str())
                && t["behind"].as_u64() == Some(0)
                && t["ahead"].as_u64().is_some_and(|v| (1..=64).contains(&v))
        }
        remote::Action::PushNewBranch {
            local_ref,
            remote_ref,
            new_oid,
            ..
        } => {
            // This genuine Observe is eligibility, NOT proof of absent config
            // or a remote branch. The same native Push owner rechecks BOTH
            // branch keys, the fresh advertisement and the full history.
            o["unborn"] == false
                && o["detached"] == false
                && o["branch"].as_str() == Some(local_ref.as_str())
                && o["head"].as_str() == Some(new_oid.as_str())
                && local_ref == remote_ref
                && value.result["tracking"]["state"] == "not-configured"
        }
    }
}
pub(super) fn action(scope: &requests::NativeScope) -> Result<local::Action, BridgeError> {
    let shared::Selected::Remote(s) = &scope.selection else {
        return Err(BridgeError::invalid());
    };
    native::action(&s.action)
}
pub(super) fn admission(
    grant: &Grant,
    fetch: Option<&crate::github_connection_session::fetch::Pins>,
    push: Option<&crate::github_connection_session::push::Pins>,
) -> bool {
    match (&grant.scope.selection, &grant.remote) {
        (shared::Selected::Remote(s), Some(approval)) => {
            approval.matches(fetch, push) && approval.account().is_ok_and(|v| v == s.account)
        }
        (shared::Selected::Files(_) | shared::Selected::Repository(_), None) => {
            fetch.is_none() && push.is_none()
        }
        _ => false,
    }
}
pub(super) fn idle_current(state: &DocumentState, grant: &Grant) -> bool {
    match (&grant.scope.selection, &grant.remote) {
        (shared::Selected::Remote(s), Some(approval)) => {
            approval.idle_current(state, &s.action, Instant::now())
        }
        (shared::Selected::Files(_) | shared::Selected::Repository(_), None) => true,
        _ => false,
    }
}

impl DocumentBinding {
    pub(crate) fn agent_git_remote_access(
        &self,
        window: &str,
    ) -> Result<MainAccess<remote::Access>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let book = self.inner.agent_git_index.book.lock()
            .map_err(|_| public(Error::StateUnknown))?;
        let access = match self.git_index_service()? {
            Some(s) => s.git_index_requests().remote_access().map_err(public)?,
            None => remote::Access::empty(),
        };
        Ok(MainAccess::new(access, book.permission_revision()))
    }
    pub(crate) fn allow_agent_git_remote(
        &self,
        window: &str,
        args: RemoteAllow,
    ) -> Result<MainAccess<remote::Access>, BridgeError> {
        if window != MAIN || args.consent_version != args.action.kind().consent() {
            return Err(BridgeError::invalid());
        }
        let action = native::action(&args.action)?;
        let (original, approval, successor) = {
            let mut state = self.lock();
            let successor = {
                let book = self.inner.agent_git_index.book.lock()
                    .map_err(|_| public(Error::StateUnknown))?;
                book.next_permission(args.expected_permission_revision)?
            };
            git_read::reconcile(&mut state);
            git_local::reconcile(&self.inner, &mut state);
            self.git_local_new_gate_for(&state, action.kind())?;
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
                || !selected(value, &args.action)
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
            let approval = Approval::select(
                &state,
                &args.project_id,
                generation,
                &args.action,
                Instant::now(),
            )?;
            (observed.original.clone(), approval, successor)
        };
        // Existing Host/service checks may do IO: no Doc/Edit/Book is held.
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
        let selection = remote::Selection::new(args.action, approval.account()?).map_err(public)?;
        let scope = Arc::new(requests::NativeScope {
            project_id: point.project_id,
            runtime_id: original.native.runtime_id.clone(),
            root: original.root.path.clone(),
            device: point.device,
            inode: point.inode,
            registration: original.native.registration_generation,
            document_revision: original.document_revision,
            input_revision: original.native.input_revision,
            read_operation_id: Some(args.read_operation_id),
            document: Arc::downgrade(&self.inner.session_identity),
            selection: selection.clone().into(),
            commit: None,
            changes: self.inner.changes.clone(),
        });
        let mut state = self.lock();
        self.git_local_new_gate_for(&state, action.kind())?;
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
        let current = Approval::select(
            &state,
            &original.native.runtime_id,
            generation,
            &selection.action,
            Instant::now(),
        )?;
        if !approval.same(&current) {
            return Err(public(Error::Conflict));
        }
        let mut book = self
            .inner
            .agent_git_index
            .book
            .lock()
            .map_err(|_| public(Error::StateUnknown))?;
        if book.next_permission(args.expected_permission_revision)? != successor
            || !repository::basis_current(&book, &state, &scope, &original)
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
        // Spend before entering the original fallible lease installer.
        book.consume_permission(args.expected_permission_revision, successor)?;
        let access = service
            .git_index_requests()
            .allow_remote(scope.clone())
            .map_err(public)?;
        book.grant = Some(Arc::new(Grant {
            scope,
            observation: original,
            remote: Some(approval),
        }));
        Ok(MainAccess::new(access, successor))
    }
    pub(crate) fn revoke_agent_git_remote(
        &self,
        window: &str,
    ) -> Result<MainAccess<remote::Access>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let advance = self.revoke_git_permission_revision_locked();
        let stop = match self.git_index_service() {
            Ok(Some(s)) => s.git_index_requests().revoke_remote().map_err(public),
            Ok(None) => Ok(remote::Access::empty()),
            Err(e) => Err(e),
        };
        advance.and_then(|revision| stop.map(|access| MainAccess::new(access, revision)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observed() -> read::Projection {
        read::Projection {
            operation_id: "git-read-1".into(),
            context: read::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "document-1".into(),
            },
            action: read::Action {
                kind: read::Kind::Observe,
                expected_revision: None,
                paths: vec![],
                staged: false,
            },
            phase: read::Phase::Settled,
            outcome: Some(read::Outcome::Ok),
            reason: None,
            result: serde_json::json!({"observation":{"revision":"a".repeat(64),"head":"d".repeat(40),"branch":"refs/heads/main","unborn":false,"detached":false,"changes":[],"remotes":["origin"],"restrictions":[]},
        "referenceRevision":"b".repeat(64),"tracking":{"state":"complete","remote":"origin","mergeRef":"refs/heads/main","localRef":"refs/remotes/origin/main","head":"c".repeat(40),"ahead":2,"behind":0},"basis":"local-refs-no-fetch"}),
        }
    }
    #[test]
    fn only_actual_observe_shape_and_exact_cached_push_target_are_eligible_data() {
        let good = observed();
        let fetch = remote::tests::selection(false).action;
        let push = remote::tests::selection(true).action;
        assert!(selected(&good, &fetch));
        assert!(selected(&good, &push));
        for which in 0..7 {
            let mut bad = good.clone();
            match which {
                0 => bad.action.kind = read::Kind::Branches,
                1 => bad.phase = read::Phase::CleanupUnknown,
                2 => bad.result["observation"]["restrictions"] = serde_json::json!(["unsupported"]),
                3 => bad.result["tracking"]["behind"] = 1.into(),
                4 => bad.result["tracking"]["head"] = "9".repeat(40).into(),
                5 => bad.result["observation"]["remotes"] = serde_json::json!(["other"]),
                _ => bad.result["referenceRevision"] = "9".repeat(64).into(),
            };
            assert!(!selected(&bad, &push));
        }
    }
    #[test]
    fn desktop_consent_is_kind_specific_and_cli_fields_cannot_select_credentials() {
        for push in [false, true] {
            let a = remote::tests::selection(push).action;
            let value = serde_json::json!({"projectId":"project-1","expectedDocumentRevision":1,"expectedPermissionRevision":"0","readOperationId":"git-read-1","action":a,"consentVersion":a.kind().consent()});
            assert!(decode_remote_allow(&serde_json::to_vec(&value).unwrap()).is_ok());
            for extra in ["token", "url", "reviewId", "root", "accountId", "window"] {
                let mut bad = value.clone();
                bad[extra] = "foreign".into();
                assert!(decode_remote_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
            }
            let mut bad = value.clone();
            bad["consentVersion"] = if push {
                remote::Kind::Fetch.consent()
            } else {
                remote::Kind::Push.consent()
            }
            .into();
            assert!(decode_remote_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    #[test]
    fn first_publication_needs_current_born_attached_unconfigured_observe_not_an_alias() {
        let mut good = observed();
        good.result["observation"]["remotes"] = serde_json::json!([]);
        good.result["tracking"] = serde_json::json!({"state":"not-configured", "remote":null,
            "mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null});
        let new = remote::tests::new_branch_selection().action;
        assert!(selected(&good, &new));
        assert!(!selected(&good, &remote::tests::selection(true).action));
        assert!(!selected(&good, &remote::tests::selection(false).action));
        assert!(!selected(&observed(), &new));
        // Another observed alias is not selected or implicitly configured by
        // this action. Actual config and advertised absence remain native.
        good.result["observation"]["remotes"] = serde_json::json!(["other"]);
        assert!(selected(&good, &new));
        for which in 0..9 {
            let mut bad = good.clone();
            match which {
                0 => bad.action.kind = read::Kind::Branches,
                1 => bad.phase = read::Phase::CleanupUnknown,
                2 => bad.result["observation"]["restrictions"] = serde_json::json!(["unsupported"]),
                3 => {
                    bad.result["observation"]["unborn"] = true.into();
                    bad.result["observation"]["head"] = serde_json::Value::Null;
                    bad.result["tracking"]["state"] = "unborn".into();
                }
                4 => {
                    bad.result["observation"]["detached"] = true.into();
                    bad.result["observation"]["branch"] = serde_json::Value::Null;
                    bad.result["tracking"]["state"] = "detached".into();
                }
                5 => bad.result["observation"]["head"] = "9".repeat(40).into(),
                6 => bad.result["observation"]["branch"] = "refs/heads/other".into(),
                7 => bad.result["referenceRevision"] = "9".repeat(64).into(),
                _ => bad.result["tracking"]["remote"] = "origin".into(),
            }
            assert!(!selected(&bad, &new), "{which}");
        }
    }
    #[test]
    fn new_branch_allow_cannot_borrow_old_consent_or_missing_remote_field() {
        let a = remote::tests::new_branch_selection().action;
        let good = serde_json::json!({"projectId":"project-1","expectedDocumentRevision":1,"expectedPermissionRevision":"0",
            "readOperationId":"git-read-1","action":a,"consentVersion":a.kind().consent()});
        assert!(decode_remote_allow(&serde_json::to_vec(&good).unwrap()).is_ok());
        for old in [false, true] {
            let old = remote::tests::selection(old).action;
            let mut bad = good.clone();
            bad["consentVersion"] = old.kind().consent().into();
            assert!(decode_remote_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
            bad = good.clone();
            bad["action"] = serde_json::to_value(&old).unwrap();
            assert!(decode_remote_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut missing = good.clone();
        missing["action"].as_object_mut().unwrap().remove("remote");
        assert!(decode_remote_allow(&serde_json::to_vec(&missing).unwrap()).is_err());
        for field in [
            "token",
            "url",
            "reviewId",
            "setUpstream",
            "absenceConfirmed",
        ] {
            let mut bad = good.clone();
            bad[field] = true.into();
            assert!(decode_remote_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
}
