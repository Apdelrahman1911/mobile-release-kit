//! Configless branch of the SAME MAIN iOS grant and retained Build relay.
//! Nothing here selects a path/session from IPC or opens a signing loan.
use super::*;
use agent::recovery as data;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    recovery: data::Selection,
    consent_version: String,
    #[serde(default, deserialize_with = "data::present")]
    confirmation: Option<String>,
    expected_permission_revision: String,
}
impl Allow {
    fn valid(&self) -> bool {
        self.consent_version == data::CONSENT
            && self.confirmation.as_deref() == self.recovery.action().confirmation()
    }
}

impl DocumentBinding {
    pub(super) fn agent_ios_recovery_current(
        &self,
        state: &DocumentState,
        grant: &Grant,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        let GrantSource::Recovery(approval) = &grant.source else {
            return Err(public(Error::Conflict));
        };
        self.service_document_gate(state)?;
        if !self
            .inner
            .android_registration_control
            .matches_epoch(grant.native.input_revision)
            || registration != grant.native.registration_generation
            || root.path != grant.native.canonical_root
            || !root
                .identity
                .posix()
                .is_ok_and(|i| i.service_identity() == (grant.native.device, grant.native.inode))
            || !Arc::ptr_eq(
                &grant.native.document_identity,
                &self.inner.session_identity,
            )
            || !self
                .inner
                .bridge
                .ios_archive
                .agent_ios_recovery_approval_current(
                    approval,
                    &self.inner.session_identity,
                    &grant.scope,
                    registration,
                    root,
                )
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    pub(super) fn allow_agent_ios_recovery(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<agent::MainAccess, BridgeError> {
        if window != MAIN || !args.valid() {
            return Err(BridgeError::invalid());
        }
        let expected =
            agent::permission_revision(&args.expected_permission_revision).map_err(public)?;
        let (native, approval) = {
            let mut state = self.lock();
            agent::permission_next(
                expected,
                self.inner
                    .agent_ios_archive_revoke_epoch
                    .load(Ordering::Acquire),
            )
            .map_err(public)?;
            if self.ios_archive_gate(&state) != wire::Availability::Available {
                return Err(crate::ios_archive_owner::unavailable());
            }
            self.inner.bridge.ios_archive.ensure_idle()?;
            let (registration, root) = self.agent_ios_registered(&mut state, &args.project_id)?;
            let native = self.service_project_locked(&state, &args.project_id)?;
            // Native matches displayed ORIGINAL inspection IDs before deriving
            // its eligible row/session. No saved-config reader or weak fallback.
            let approval = self.inner.bridge.ios_archive.approve_agent_ios_recovery(
                args.project_id,
                args.recovery,
                &self.inner.session_identity,
                registration,
                &root,
            )?;
            if approval
                .retained_bytes()
                .is_none_or(|n| n > crate::agent_build_requests::RECOVERY_BINDING_BYTES)
            {
                return Err(public(Error::StateUnknown));
            }
            (native, approval)
        };
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let (point, read) = service
            .ios_recovery_point_with_read(&native.runtime_id)
            .map_err(public)?;
        let scope = Arc::new(agent::NativeScope {
            project_id: point.project_id.clone(),
            runtime_id: native.runtime_id.clone(),
            root: native.canonical_root.clone(),
            device: native.device,
            inode: native.inode,
            registration: native.registration_generation,
            input_revision: native.input_revision,
            document: Arc::downgrade(&self.inner.session_identity),
            observation_revision: point.revision,
            review: approval.review().clone().into(),
            read: Some(read.clone()),
            input: crate::agent_build_requests::NativeInput::Recovery,
            changes: self.inner.changes.clone(),
        });
        if !scope.matches(&point) || !scope.matches_read(&read) {
            return Err(public(Error::Conflict));
        }
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            native,
            source: GrantSource::Recovery(approval),
        });
        let mut state = self.lock();
        if self.ios_archive_gate(&state) != wire::Availability::Available {
            return Err(crate::ios_archive_owner::unavailable());
        }
        self.inner.bridge.ios_archive.ensure_idle()?;
        let (registration, root) =
            self.agent_ios_registered(&mut state, &grant.native.runtime_id)?;
        self.agent_ios_recovery_current(&state, &grant, registration, &root)?;
        let next = agent::permission_next(
            expected,
            self.inner
                .agent_ios_archive_revoke_epoch
                .load(Ordering::Acquire),
        )
        .map_err(public)?;
        if let Some(original) = self.inner.agent_ios_archive_service.get() {
            if original.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_ios_archive_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        let access = service.build_requests().allow(scope).map_err(public)?;
        state.agent_ios_archive_grant = Some(grant);
        self.inner
            .agent_ios_archive_revoke_epoch
            .store(next, Ordering::Release);
        Ok(agent::MainAccess::new(access, next))
    }
    pub(super) fn admit_agent_ios_recovery(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<agent::Entry>,
        kind: agent::ClaimKind,
        grant: &Arc<Grant>,
    ) -> Result<(), BridgeError> {
        let GrantSource::Recovery(approval) = &grant.source else {
            return Err(public(Error::Conflict));
        };
        if entry.family() != agent::FAMILY || !std::ptr::eq(entry.scope(), grant.scope.as_ref()) {
            return Err(public(Error::Conflict));
        }
        let current_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&grant.native)
            .map_err(public)?;
        if !Arc::ptr_eq(service, &current_service) {
            return Err(public(Error::Conflict));
        }
        match kind {
            agent::ClaimKind::Prepare => {
                let (point, read) = service
                    .ios_recovery_point_with_read(&grant.native.runtime_id)
                    .map_err(public)?;
                if !entry.prepare_live()
                    || !entry.scope().matches(&point)
                    || !entry.scope().matches_read(&read)
                {
                    return Err(public(Error::Conflict));
                }
            }
            agent::ClaimKind::Start => {
                if !entry.start_live() {
                    return Err(public(Error::Expired));
                }
                // SAME source writer before effects. This intentionally stales
                // the old observation; status/history never refreshes it.
                service
                    .consume_build_observation(entry.scope())
                    .map_err(public)?;
            }
        }
        let mut state = self.lock();
        let gate = self.ios_archive_gate(&state);
        if gate != wire::Availability::Available {
            return Err(crate::ios_archive_owner::unavailable());
        }
        let (registration, root) =
            self.agent_ios_registered(&mut state, &grant.native.runtime_id)?;
        self.agent_ios_recovery_current(&state, grant, registration, &root)?;
        if state
            .agent_ios_archive_grant
            .as_ref()
            .is_none_or(|g| !Arc::ptr_eq(g, grant))
        {
            return Err(public(Error::Conflict));
        }
        match kind {
            agent::ClaimKind::Prepare => {
                self.inner.bridge.ios_archive.prepare_agent_ios_recovery(
                    entry.clone(),
                    approval.clone(),
                    registration,
                    root,
                    gate,
                )?;
            }
            agent::ClaimKind::Start => {
                let admitted = self.inner.bridge.ios_archive.start_agent_ios_recovery(
                    entry,
                    Some((registration, root)),
                    gate,
                )?;
                drop(state);
                let _ = admitted.release(); // only SAME admitted GO, after Doc unlock
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_allow_is_exact_action_confirmation_and_displayed_pair_not_session_or_config() {
        let value = serde_json::json!({"projectId":"p","recovery":{"action":"account","inspection":{
            "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32)}},
            "consentVersion":data::CONSENT,"confirmation":data::ACCOUNT_CONFIRMATION,"expectedPermissionRevision":"7"});
        assert!(serde_json::from_value::<Allow>(value.clone())
            .unwrap()
            .valid());
        for (field, v) in [
            ("confirmation", Value::Null),
            ("session", serde_json::json!("c".repeat(32))),
            ("savedConfig", Value::Null),
            ("manual", serde_json::json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = v;
            assert!(serde_json::from_value::<Allow>(bad).is_err());
        }
        let mut bad = value;
        bad["confirmation"] = serde_json::json!(data::PROJECT_CONFIRMATION);
        assert!(!serde_json::from_value::<Allow>(bad).unwrap().valid());
        let inspect = serde_json::json!({"projectId":"p","recovery":{"action":"inspect"},
            "consentVersion":data::CONSENT,"expectedPermissionRevision":"0"});
        assert!(serde_json::from_value::<Allow>(inspect).unwrap().valid());
    }
}
