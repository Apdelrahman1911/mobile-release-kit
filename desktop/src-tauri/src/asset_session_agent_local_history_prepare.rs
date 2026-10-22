//! The original Store relay and real Document perform read-only History Prepare.
//! No invented Webview, credential/native session, dispatcher or timer.
use super::*;
use crate::{
    local_release_history_protocol as wire, saved_command_owner::HistoryPreparationLink,
    service_local_history_prepare_protocol as prepare,
    service_store_requests::history::preparation as requests,
};

impl DocumentBinding {
    /// Memory-only Host lookup, always OFF Doc. This never starts a Host or
    /// creates/renews READ. The existing weak cell is single-original only.
    pub(in crate::asset_session) fn history_listening_service(
        &self,
    ) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        let current = match self
            .inner
            .bridge
            .application_service
            .configuration_service()
        {
            Ok(s) => s,
            Err(Error::Unavailable) => {
                return if self.inner.agent_store_service.get().is_none() {
                    Ok(None)
                } else {
                    Err(public(Error::Unavailable))
                }
            }
            Err(e) => return Err(public(e)),
        };
        if let Some(old) = self.inner.agent_store_service.get() {
            if old.as_ptr() != Arc::as_ptr(&current) {
                return Err(public(Error::Conflict));
            }
        } else if self
            .inner
            .agent_store_service
            .set(Arc::downgrade(&current))
            .is_err()
            && self
                .inner
                .agent_store_service
                .get()
                .is_none_or(|old| old.as_ptr() != Arc::as_ptr(&current))
        {
            return Err(public(Error::StateUnknown));
        }
        Ok(Some(current))
    }
    fn history_preparation_current(
        &self,
        state: &mut DocumentState,
        link: &HistoryPreparationLink,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        link.entry.current(Instant::now()).map_err(public)?;
        let (g, root) = self
            .registry_result(
                state,
                self.inner
                    .bridge
                    .native_project(&link.entry.scope().saved.runtime_id),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&link.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(link.input_revision)
            || g != link.registration
            || root.path != link.entry.scope().saved.root
            || !root.identity.posix().is_ok_and(|p| {
                p.service_identity()
                    == (
                        link.entry.scope().saved.device,
                        link.entry.scope().saved.inode,
                    )
            })
            || link.document.as_ptr() != Arc::as_ptr(&self.inner.session_identity)
            || !link
                .consent
                .upgrade()
                .is_some_and(|c| c.matches(&self.inner, state, g, &root))
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    fn admit_history_preparation(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<requests::Entry>,
    ) -> Result<(), BridgeError> {
        entry.current(Instant::now()).map_err(public)?;
        let (native, stamp) = {
            let state = self.lock();
            self.service_document_gate(&state)?;
            if self.local_history_gate(&state) != wire::Availability::Available
                || self.history_delegate_owner().busy()
            {
                return Err(public(Error::Busy));
            }
            let native = self.service_project_locked(&state, &entry.scope().saved.runtime_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            (native, edit.stamp()?)
        };
        let same = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        if !Arc::ptr_eq(&same, service) {
            return Err(public(Error::Conflict));
        }
        let point = service
            .version_reserve_point(&native.runtime_id)
            .map_err(public)?;
        if !entry.scope().matches(&point.saved, &point.read) {
            return Err(public(Error::Conflict));
        }
        let input = native_prepare(&native.runtime_id, entry.selection())?;
        let mut state = self.lock();
        self.service_document_gate(&state)?;
        let gate = self.local_history_gate(&state);
        if gate != wire::Availability::Available || self.history_delegate_owner().busy() {
            return Err(public(Error::Busy));
        }
        let (g, root) = self
            .registry_result(
                &mut state,
                self.inner.bridge.native_project(&native.runtime_id),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(native.input_revision)
            || g != native.registration_generation
            || root.path != native.canonical_root
            || !root
                .identity
                .posix()
                .is_ok_and(|v| v.service_identity() == (native.device, native.inode))
            || !Arc::ptr_eq(&native.document_identity, &self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        entry.current(Instant::now()).map_err(public)?;
        let consent = self.capture_history_consent(&state, &input, g, &root);
        self.history_delegate_owner().prepare_agent_history(
            input,
            g,
            root,
            gate,
            consent,
            entry.clone(),
            native,
            stamp,
        )?;
        Ok(())
    }
    pub(in crate::asset_session) fn tick_history_preparation(
        &self,
        service: &Arc<ApplicationService>,
    ) {
        self.check_history_preparation(service);
        match service.store_requests().claim_history_preparation() {
            Ok(Some(claim)) => {
                let result = self.admit_history_preparation(service, claim.entry());
                if result.is_err() {
                    let reason = claim
                        .entry()
                        .stop_at(Instant::now())
                        .map_or(p::Reason::NativeRefused, |(r, _)| r);
                    if self
                        .history_delegate_owner()
                        .history_preparation_link()
                        .is_some_and(|l| Arc::ptr_eq(&l.entry, claim.entry()))
                    {
                        self.history_delegate_owner().stop_history_preparation(
                            claim.entry(),
                            reason,
                            Instant::now(),
                        );
                    } else {
                        claim.entry().refused(reason);
                    }
                }
                claim.returned(); // actual synchronous body returned, not native retirement
            }
            Ok(None) => {}
            Err(_) => service.store_requests().fence(),
        }
    }
    fn check_history_preparation(&self, service: &Arc<ApplicationService>) {
        let Some(link) = self.history_delegate_owner().history_preparation_link() else {
            return;
        };
        if link.entry.handed_off() {
            return;
        }
        let point = service.version_reserve_point(&link.entry.scope().saved.runtime_id);
        let current = point.is_ok_and(|p| link.entry.scope().matches(&p.saved, &p.read))
            && self
                .history_preparation_current(&mut self.lock(), &link)
                .is_ok();
        if !current {
            self.history_delegate_owner().stop_history_preparation(
                &link.entry,
                p::Reason::ContextChanged,
                Instant::now(),
            );
        } else {
            let _ = self
                .history_delegate_owner()
                .publish_history_preparation(&link.entry);
        }
    }
    pub(in crate::asset_session) fn stop_history_preparation_for_host(&self) {
        if let Some(link) = self.history_delegate_owner().history_preparation_link() {
            self.history_delegate_owner().stop_history_preparation(
                &link.entry,
                p::Reason::PermissionRevoked,
                Instant::now(),
            );
        }
    }
    pub(super) fn history_comparison(
        &self,
        state: &mut DocumentState,
        entry: Arc<requests::Entry>,
        point_current: bool,
    ) -> Result<prepare::Comparison, BridgeError> {
        let link = self
            .history_delegate_owner()
            .history_preparation_link()
            .filter(|l| Arc::ptr_eq(&l.entry, &entry));
        let live = if let Some(link) = link {
            if entry.handed_off() {
                None
            } else if !point_current || self.history_preparation_current(state, &link).is_err() {
                self.history_delegate_owner().stop_history_preparation(
                    &entry,
                    p::Reason::ContextChanged,
                    Instant::now(),
                );
                None
            } else {
                self.history_delegate_owner()
                    .publish_history_preparation(&entry)?
            }
        } else {
            None
        };
        let result = prepare::Comparison {
            runtime_project_id: entry.scope().saved.runtime_id.clone(),
            request: entry.status().map_err(public)?,
            live,
        };
        result.validate().map_err(public)?;
        Ok(result)
    }
}
fn native_prepare(runtime: &str, s: &prepare::Selection) -> Result<wire::Prepare, BridgeError> {
    if !s.valid() {
        return Err(BridgeError::invalid());
    }
    let action = match s.kind {
        p::Kind::Enroll => wire::Action::Enroll,
        p::Kind::Verify => wire::Action::Verify,
        p::Kind::ReviewInputs => wire::Action::ReviewInputs,
        p::Kind::ReviewPrepared => wire::Action::ReviewPrepared,
        p::Kind::ReviewExecution => wire::Action::ReviewExecution,
        p::Kind::ReviewReconcile => wire::Action::ReviewReconcile,
        p::Kind::ReviewRecovery => wire::Action::ReviewRecovery,
        p::Kind::ReviewStagePrepared => wire::Action::ReviewStagePrepared,
        p::Kind::ReviewStageExecution => wire::Action::ReviewStageExecution,
        p::Kind::ReviewExternalReadiness => wire::Action::ReviewExternalReadiness,
    };
    Ok(wire::Prepare {
        project_id: runtime.into(),
        action,
        candidate_operation_id: s.candidate_operation_id.clone(),
        stage_operation_id: s.stage_operation_id.clone(),
        platform: s.platform.map(|p| match p {
            p::Platform::Android => wire::CandidatePlatform::Android,
            p::Platform::Ios => wire::CandidatePlatform::Ios,
        }),
        execution_mode: wire::ExecutionMode::Local,
    })
}
pub(in crate::asset_session) fn flush(service: &ApplicationService) -> Result<(), Error> {
    for entry in service.store_requests().history_preparations()? {
        let Some(history) = entry.claim_history()? else {
            continue;
        };
        // Preparation request ID, not a fictitious native execution. Same
        // history writer ACK is mandatory before usable Prepared publication.
        let result = if history.first {
            service.begin_operation(
                &entry.scope().saved.runtime_id,
                entry.origin().request_id.clone(),
                crate::service_protocol::Action::ObserveProject,
                history.data.state,
                history.data.settlement,
            )
        } else {
            service.publish_operation(
                &entry.scope().saved.runtime_id,
                entry.origin().request_id.clone(),
                crate::service_protocol::Action::ObserveProject,
                history.data.state,
                history.data.settlement,
            )
        };
        history.returned(result)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sixteen_selected_shapes_enter_only_actual_registered_runtime_history_contexts() {
        let uuid = "12345678-1234-4234-8234-123456789abc";
        let mut count = 0;
        for kind in [
            p::Kind::Enroll,
            p::Kind::Verify,
            p::Kind::ReviewInputs,
            p::Kind::ReviewPrepared,
            p::Kind::ReviewExecution,
            p::Kind::ReviewReconcile,
            p::Kind::ReviewRecovery,
            p::Kind::ReviewStagePrepared,
            p::Kind::ReviewStageExecution,
            p::Kind::ReviewExternalReadiness,
        ] {
            for platform in [None, Some(p::Platform::Android), Some(p::Platform::Ios)] {
                let selected = !matches!(kind, p::Kind::Enroll | p::Kind::Verify);
                let s = prepare::Selection {
                    kind,
                    platform,
                    candidate_operation_id: (selected && !kind.stage()).then(|| uuid.into()),
                    stage_operation_id: kind.stage().then(|| uuid.into()),
                };
                let result = native_prepare("registered-runtime-p1", &s);
                if s.valid() {
                    let native = result.unwrap();
                    assert!(native.context().valid());
                    assert_eq!(native.project_id, "registered-runtime-p1");
                    assert_ne!(native.project_id, "1".repeat(32));
                    assert_ne!(native.action, wire::Action::AbandonInputs);
                    assert_eq!(
                        native.context().selected_operation_id(),
                        selected.then_some(uuid)
                    );
                    assert_eq!(native.execution_mode, wire::ExecutionMode::Local);
                    count += 1;
                } else {
                    assert!(result.is_err());
                }
            }
        }
        assert_eq!(count, 16);
    }
    #[test]
    fn existing_main_lookup_accepts_only_empty_or_complete_exact_origin_and_no_material() {
        let q = serde_json::json!({"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
        assert!(super::super::decode::<super::super::AccessQuery>(b"{}")
            .unwrap()
            .exact()
            .is_none());
        let v: super::super::AccessQuery =
            super::super::decode(&serde_json::to_vec(&q).unwrap()).unwrap();
        assert_eq!(v.exact().unwrap().project_id.as_str(), "1".repeat(32));
        for field in ["projectId", "serviceInstance", "requestId"] {
            let mut missing = q.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(super::super::decode::<super::super::AccessQuery>(
                &serde_json::to_vec(&missing).unwrap()
            )
            .is_err());
        }
        for bad in [
            serde_json::json!({"query":q}),
            serde_json::json!({"projectId":null}),
            serde_json::json!({"root":"/not-input"}),
            serde_json::json!({"kind":"verify"}),
        ] {
            assert!(super::super::decode::<super::super::AccessQuery>(
                &serde_json::to_vec(&bad).unwrap()
            )
            .is_err());
        }
        let allow = serde_json::json!({"kind":"verify","operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"expectedStatusRevision":2,"expectedPermissionRevision":"0","consentVersion":"agent-local-history-verify-once-v1","preparationOrigin":q});
        let a: super::super::Allow =
            super::super::decode(&serde_json::to_vec(&allow).unwrap()).unwrap();
        assert!(a.preparation_origin.is_some());
        let mut bad = allow;
        bad["preparationOrigin"] = serde_json::Value::Null;
        assert!(
            super::super::decode::<super::super::Allow>(&serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
}
