//! Thin actual-main-window delegation to the existing version editor. No
//! worker, source read, handoff constructor or second publication chain.
use super::*;
use crate::{
    application_service::ApplicationService, application_service_host::NativeProject,
    edit_owner::VersionEditDecision, service_version_edit_protocol as p,
    service_version_edit_requests as requests,
};
use serde::Deserialize;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn refused() -> BridgeError {
    BridgeError::new(
        "cli_access_changed",
        "Use the same prepared version review and original Desktop read permission.",
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    original: p::Original,
    status_revision: u32,
    nonce: crate::service_protocol::Id,
    consent: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    nonce: crate::service_protocol::Id,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Apply {
    intent: String,
    origin: p::Query,
}
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > p::REQUEST_BYTES {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    if !value.is_object() {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn status_request(body: Value) -> Result<Option<p::Query>, BridgeError> {
    if body.as_object().is_some_and(|v| v.is_empty()) {
        Ok(None)
    } else {
        serde_json::from_value(body)
            .map(Some)
            .map_err(|_| BridgeError::invalid())
    }
}
pub(crate) fn apply_request(body: Value) -> Result<p::Query, BridgeError> {
    p::bounded(&body, p::REQUEST_BYTES).map_err(public)?;
    let args: Apply = serde_json::from_value(body).map_err(|_| BridgeError::invalid())?;
    if args.intent != "agent-version-edit" {
        return Err(BridgeError::invalid());
    }
    Ok(args.origin)
}
pub(crate) fn allow_request(body: Value) -> Result<Allow, BridgeError> {
    p::bounded(&body, p::REQUEST_BYTES).map_err(public)?;
    let a: Allow = serde_json::from_value(body).map_err(|_| BridgeError::invalid())?;
    if !crate::protocol::valid_id(&a.project_id) || a.consent != p::CONSENT {
        return Err(BridgeError::invalid());
    }
    Ok(a)
}
pub(crate) fn revoke_request(body: Value) -> Result<Revoke, BridgeError> {
    serde_json::from_value(body).map_err(|_| BridgeError::invalid())
}
impl DocumentBinding {
    fn version_edit_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        // Existing activated Host only; this cannot initialize/enable access.
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_version_edit_status(
        &self,
        q: Option<&p::Query>,
    ) -> Result<p::Access, BridgeError> {
        let service = self.version_edit_service()?;
        // Resolve ALL comparison fields from the exact old Entry, never mix
        // a later current grant with an older request's native final metadata.
        let access = match q {
            Some(q) => service.version_edit_requests().access_for(q),
            None => service.version_edit_requests().access(),
        }
        .map_err(public)?;
        access.validate().map_err(public)?;
        Ok(access)
    }
    pub(crate) fn agent_version_edit_relay_lost(&self) {
        self.inner.bridge.edits.version_edit_relay_lost();
    }
    fn version_edit_peers(&self, state: &DocumentState, session: &str) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        if !self.inner.bridge.supervisor.can_exit()
            || state
                .slot
                .as_ref()
                .is_some_and(|s| s.phase != Phase::Idle || !s.owner.resources_settled())
            || gh_auth::pending(state)
            || git_read::pending(state)
            || git_local::pending(state)
            || version_enrollment::pending(state)
        {
            return Err(refused());
        }
        self.release_version_prepared_current(state, session)?;
        self.version_edit_memory(state)
    }
    fn version_edit_memory(&self, state: &DocumentState) -> Result<(), BridgeError> {
        let retained =
            lookup_memory::retained_document_bytes(&self.inner, state).map_err(|_| refused())?;
        let additional = {
            #[cfg(any(
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(
                    target_os = "macos",
                    target_pointer_width = "64",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )
            ))]
            {
                installation_memory::additional_document_bytes(self, state)
                    .map_err(|_| refused())?
            }
            #[cfg(not(any(
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(
                    target_os = "macos",
                    target_pointer_width = "64",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )
            )))]
            {
                return Err(refused());
            }
        };
        let edits = self.inner.bridge.edits.version_agent_edit_backing()?;
        if retained
            .checked_add(additional)
            .and_then(|n| n.checked_add(edits))
            .is_none_or(|n| n > SESSION_BYTES)
        {
            return Err(refused());
        }
        Ok(())
    }
    fn version_edit_same(
        &self,
        state: &DocumentState,
        old: &NativeProject,
    ) -> Result<(), BridgeError> {
        let now = self.service_project_locked(state, &old.runtime_id)?;
        if now.registration_generation != old.registration_generation
            || now.canonical_root != old.canonical_root
            || now.device != old.device
            || now.inode != old.inode
            || now.input_revision != old.input_revision
            || !Arc::ptr_eq(&now.document_identity, &old.document_identity)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn allow_agent_version_edit_apply(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        let service = self.version_edit_service()?; // OFF Doc/Edit.
        let (project, original) = {
            let state = self.lock();
            self.version_edit_peers(&state, args.original.session_id.as_str())?;
            (
                self.service_project_locked(&state, &args.project_id)?,
                self.inner.bridge.edits.version_edit_prepared(
                    window,
                    &args.original,
                    args.status_revision,
                )?,
            )
        };
        let point = service
            .version_reserve_point(&project.runtime_id)
            .map_err(public)?; // OFF Doc/Edit.
        if point.saved.root != project.canonical_root
            || point.saved.device != project.device
            || point.saved.inode != project.inode
        {
            return Err(refused());
        }
        {
            let state = self.lock();
            self.version_edit_peers(&state, args.original.session_id.as_str())?;
            self.version_edit_same(&state, &project)?;
            self.inner.bridge.edits.version_edit_install(
                window,
                original,
                project,
                requests::Scope {
                    saved: point.saved,
                    read: point.read,
                },
                args.nonce,
                &service,
            )?;
        }
        service.version_edit_requests().access().map_err(public)
    }
    pub(crate) fn revoke_agent_version_edit(
        &self,
        _window: &str,
        args: Revoke,
    ) -> Result<p::Access, BridgeError> {
        let service = self.version_edit_service()?;
        service
            .version_edit_requests()
            .revoke(&args.nonce, Instant::now())
            .map_err(public)?;
        service.version_edit_requests().access().map_err(public)
    }
    pub(crate) fn apply_agent_version_edit(
        &self,
        window: &str,
        q: &p::Query,
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        let service = self.version_edit_service()?;
        let entry = service.version_edit_requests().entry(q).map_err(public)?;
        if !entry.pending().map_err(public)? {
            return self.inner.bridge.edits.release_version_status();
        }
        let sid = entry.lease.review.original.session_id.as_str();
        let plan = entry.lease.review.original.plan_token.as_str();
        let result = (|| {
            service
                .version_edit_current(&entry.lease.scope)
                .map_err(public)?; // OFF Doc/Edit, before publisher.
            self.apply_version_edit_permitted(window, sid, plan, Some(&entry))
        })();
        if result.is_err() {
            let _ = entry.cancel(Instant::now());
        } // Same watchdog, never another owner.
        result
    }
    pub(crate) fn apply_version_edit_permitted(
        &self,
        window: &str,
        session: &str,
        plan: &str,
        entry: Option<&Arc<requests::Entry>>,
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        // This entire early cut is OUTSIDE all ordinary Release error tails.
        let decision = {
            let state = self.lock();
            self.version_edit_peers(&state, session)?;
            if let Some(link)=self.inner.bridge.edits.version_prepare_for_session(window,session)?{
                self.version_prepare_current_locked(&state,&link)?;
            }else{
                let link = self.inner.bridge.edits.version_edit_link(window, session)?;
                self.version_edit_same(&state, &link.project)?;
            }
            self.inner
                .bridge
                .edits
                .version_edit_preclaim(window, session, plan, entry)?
        };
        let VersionEditDecision::Apply(claim) = decision else {
            return self.inner.bridge.edits.release_version_status();
        };
        let result = self.release_version_phase_admit(
            session,
            crate::edit_owner::ReservedVersionStep::Apply,
            |b, root, publisher| {
                b.edits
                    .apply_version_edit_claimed(publisher, window, session, plan, root, &claim)
            },
        );
        if result.is_err() {
            self.inner.bridge.edits.version_edit_claim_failed(&claim);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: char) -> String {
        n.to_string().repeat(32)
    }
    #[test]
    fn actual_raw_variant_requires_only_exact_original_not_values_or_window() {
        let origin =
            serde_json::json!({"projectId":id('1'),"serviceInstance":id('2'),"requestId":id('3')});
        let raw = serde_json::json!({"intent":"agent-version-edit","origin":origin});
        assert!(apply_request(raw_request(&serde_json::to_vec(&raw).unwrap()).unwrap()).is_ok());
        assert!(
            raw_request(br#"{"intent":"agent-version-edit","intent":"agent-version-edit"}"#)
                .is_err()
        );
        assert!(raw_request(&vec![b' '; p::REQUEST_BYTES + 1]).is_err());
        assert!(raw_request(b"null").is_err());
        assert!(apply_request(raw.clone()).is_ok());
        assert!(status_request(serde_json::json!({})).unwrap().is_none());
        assert!(status_request(origin.clone()).unwrap().is_some());
        for value in [
            Value::Null,
            serde_json::json!({"origin":origin}),
            serde_json::json!({"intent":"edit","origin":origin}),
        ] {
            assert!(apply_request(value).is_err());
        }
        for field in ["path", "values", "window", "candidateId", "planToken"] {
            let mut v = raw.clone();
            v[field] = serde_json::json!("caller DATA");
            assert!(apply_request(v).is_err());
        }
        let allow = serde_json::json!({"projectId":"native-project","original":{"sessionId":id('4'),"ownerGeneration":id('5'),"revision":id('6'),"planToken":id('7')},"statusRevision":3,"nonce":id('8'),"consent":p::CONSENT});
        assert!(allow_request(allow.clone()).is_ok());
        let mut old = allow;
        old["consent"] = serde_json::json!("agent-exact-prepared-configuration-apply-v1");
        assert!(allow_request(old).is_err());
    }
    #[test]
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    fn real_document_and_original_edit_future_include_retained_buffer_and_overflow() {
        let bridge = Arc::new(DesktopBridge::new(
            "/never-opened-version-delegation-data".into(),
        ));
        let doc = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let mut state = doc.lock();
        let base = lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap();
        let extra_base = installation_memory::additional_document_bytes(&doc, &state).unwrap();
        let edits = bridge.edits.version_agent_edit_backing().unwrap();
        eprintln!("Version delegation DATA: document={base}; additional={extra_base}; originalEditFuture={edits}; cap={SESSION_BYTES}");
        assert!(base > 0 && extra_base > 0 && edits > 0);
        assert!(doc.version_edit_memory(&state).is_ok());
        // A real selected DATA buffer/observation, not a granted credential or
        // artificial numeric census. Small legitimate use remains reachable.
        let observation = credential_format::inspect(
            credential_format::FileKind::AndroidKeystore,
            &[],
            &mut || false,
        )
        .ok()
        .unwrap();
        state.records.push(Record {
            key: RecordKey {
                id: Token("inert-version-memory".into()),
                revision: 1,
            },
            payload: Arc::new(Payload {
                kind: Kind::AndroidKeystore,
                fields: None,
                material: Some(Arc::new(Material {
                    origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                        Vec::with_capacity(1024 * 1024),
                    )),
                    observation,
                })),
            }),
            mutation_pending: false,
        });
        let retained = lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap();
        assert!(retained >= base + 1024 * 1024 + RECORD_METADATA_BYTES);
        assert!(doc.version_edit_memory(&state).is_ok());
        // Real retained comparison backing omitted by the lookup census. This
        // is not an evidence observation, grant, saved lane or native receipt.
        let mut selection_id = "a".repeat(32);
        selection_id.reserve_exact(64 * 1024);
        let selection_capacity = selection_id.capacity();
        let selection_pointer = selection_id.as_ptr();
        state.evidence.phase = evidence_wire::Phase::Refused;
        state.evidence.operation = Some(EvidenceBinding {
            operation_id: 1,
            kind: evidence_wire::OperationKind::Observe,
            selection_id: Some(selection_id),
            epoch: 0,
            purpose: EvidencePurpose::Candidate,
        });
        let additional = installation_memory::additional_document_bytes(&doc, &state).unwrap();
        assert!(additional >= extra_base + selection_capacity);
        assert_eq!(
            lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap(),
            retained
        );
        assert!(doc.version_edit_memory(&state).is_ok());
        state.evidence.phase = evidence_wire::Phase::Unknown;
        assert!(doc.version_edit_memory(&state).is_err());
        state.evidence.phase = evidence_wire::Phase::Refused;
        let grow = SESSION_BYTES
            .checked_sub(
                retained
                    .checked_add(additional)
                    .unwrap()
                    .checked_add(edits)
                    .unwrap(),
            )
            .unwrap()
            + 1;
        let payload = Arc::get_mut(&mut state.records[0].payload).unwrap();
        let material = Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
        let MaterialOrigin::Selected(source) = &mut material.origin else {
            panic!("original DATA")
        };
        let old = source.bytes.capacity();
        source.bytes.reserve_exact(old + grow);
        let after = lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap();
        assert!(after >= retained + grow);
        assert!(after.checked_add(edits).unwrap() <= SESSION_BYTES); // Old omitted-extra gate would admit.
        assert!(doc.version_edit_memory(&state).is_err());
        assert_eq!(
            state
                .evidence
                .operation
                .as_ref()
                .unwrap()
                .selection_id
                .as_ref()
                .unwrap()
                .as_ptr(),
            selection_pointer
        );
        assert!(after.checked_add(usize::MAX).is_none());
        state.retiring = true;
        assert!(doc.version_edit_memory(&state).is_err());
    }
}
