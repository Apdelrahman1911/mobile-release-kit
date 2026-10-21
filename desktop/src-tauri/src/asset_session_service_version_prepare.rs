//! Real main-Webview continuations; the service/relay only carries bounded
//! request DATA. No synthetic Window, reader, executor or reservation exists.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::{SavedEditStamp, VersionPrepareLink, VersionPrepareStep},
    service_version_edit_prepare_protocol as p,
    service_version_edit_prepare_requests::{Entry, Kind},
};
use serde::Deserialize;
use std::sync::Weak;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn refused() -> BridgeError {
    BridgeError::new("cli_access_changed","Keep the original version request, Desktop source and READ permission. No edit was replayed.")
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    intent: String,
    origin: p::Query,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepare {
    intent: String,
    origin: p::Query,
    draft_revision: u32,
    baseline_generation: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Status {
    intent: String,
    #[serde(deserialize_with = "nullable")]
    origin: Option<p::Query>,
}
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn open_request(v: Value) -> Result<p::Query, BridgeError> {
    crate::service_version_edit_protocol::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let a: Open = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if a.intent != "agent-version-prepare" {
        return Err(BridgeError::invalid());
    }
    Ok(a.origin)
}
pub(crate) fn prepare_request(v: Value) -> Result<(p::Query, (u32, u32)), BridgeError> {
    crate::service_version_edit_protocol::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let a: Prepare = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if a.intent != "agent-version-prepare"
        || a.draft_revision == u32::MAX
        || a.baseline_generation == u32::MAX
    {
        return Err(BridgeError::invalid());
    }
    Ok((a.origin, (a.draft_revision, a.baseline_generation)))
}
pub(crate) fn status_request(v: Value) -> Result<Option<p::Query>, BridgeError> {
    crate::service_version_edit_protocol::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let a: Status = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if a.intent != "preparation" {
        return Err(BridgeError::invalid());
    }
    Ok(a.origin)
}
pub(crate) struct VersionPrepareGate {
    document: Weak<Inner>,
    stamp: SavedEditStamp,
}
impl VersionPrepareGate {
    pub(crate) fn same_publisher(&self, p: &RegistrationPublisher) -> bool {
        self.document
            .upgrade()
            .is_some_and(|d| p.same_slot(&d.android_registration_control))
    }
    pub(crate) fn epoch(&self) -> Result<u64, BridgeError> {
        self.document
            .upgrade()
            .ok_or_else(refused)?
            .android_registration_control
            .epoch()
    }
    pub(crate) fn current(&self, old: &NativeProject) -> Result<(), BridgeError> {
        let inner = self.document.upgrade().ok_or_else(refused)?;
        let state = inner.state.try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => {
                BridgeError::new("busy", "Wait for the original document.")
            }
            _ => BridgeError::cleanup_unknown(),
        })?;
        DocumentBinding {
            inner: inner.clone(),
        }
        .version_prepare_root(&state, old)
    }
}
impl DocumentBinding {
    fn version_prepare_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_version_prepare_status(
        &self,
        q: Option<&p::Query>,
    ) -> Result<Option<p::Status>, BridgeError> {
        self.version_prepare_service()?
            .version_edit_requests()
            .preparation_status(q)
            .map_err(public)
    }
    pub(crate) fn cancel_agent_version_prepare(
        &self,
        window: &str,
        q: &p::Query,
    ) -> Result<Option<p::Status>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let at = Instant::now();
        let service = self.version_prepare_service()?;
        let e = service
            .version_edit_requests()
            .preparation(q)
            .map_err(public)?;
        self.inner
            .bridge
            .edits
            .version_prepare_cancel(window, &e, at)?;
        e.status().map(Some).map_err(public)
    }
    fn version_prepare_root(
        &self,
        state: &DocumentState,
        old: &NativeProject,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        if state.retiring
            || state.quit_pending
            || state.lock_pending
            || state.maintenance.closed()
            || !Arc::ptr_eq(&self.inner.session_identity, &old.document_identity)
        {
            return Err(refused());
        }
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&old.runtime_id)
            .map_err(|_| refused())?;
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| refused())?
            .service_identity();
        if generation != old.registration_generation
            || root.path != old.canonical_root
            || device != old.device
            || inode != old.inode
        {
            return Err(refused());
        }
        Ok(())
    }
    fn version_prepare_peers(
        &self,
        state: &DocumentState,
        opening: bool,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        state.github.setup_ensure_idle()?;
        if !self.inner.bridge.supervisor.can_exit()
            || state.github.native_work_pending()
            || state
                .slot
                .as_ref()
                .is_some_and(|s| s.phase != Phase::Idle || !s.owner.resources_settled())
            || gh_auth::pending(state)
            || git_read::pending(state)
            || git_local::pending(state)
            || version_enrollment::pending(state)
            || version_allocation::pending(state)
            || opening && !self.inner.bridge.edits.can_exit()
        {
            return Err(refused());
        }
        self.version_prepare_memory(state)
    }
    fn version_prepare_memory(&self, state: &DocumentState) -> Result<(), BridgeError> {
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            let old = lookup_memory::retained_document_bytes(&self.inner, state)
                .map_err(|_| refused())?;
            let extra = installation_memory::additional_document_bytes(self, state)
                .map_err(|_| refused())?;
            let edit = self.inner.bridge.edits.version_prepare_edit_backing()?;
            if old
                .checked_add(extra)
                .and_then(|n| n.checked_add(edit))
                .is_none_or(|n| n > SESSION_BYTES)
            {
                return Err(BridgeError::new("cli_access_busy","Version preparation storage is full. Preserve existing drafts and originals; use the ordinary editor after they settle."));
            }
            Ok(())
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
            let _ = state;
            Err(refused())
        }
    }
    pub(super) fn version_prepare_open_locked(
        &self,
        state: &DocumentState,
        link: &VersionPrepareLink,
        publisher: &RegistrationPublisher,
    ) -> Result<(), BridgeError> {
        self.version_prepare_peers(state, true)?;
        self.version_prepare_root(state, &link.project)?;
        if !link.gate.same_publisher(publisher)
            || publisher.tool_source_epoch()? != link.project.input_revision
            || !link.entry.admitting(Kind::Open)
            || !self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?
                .matches(&link.gate.stamp)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn version_prepare_current_locked(
        &self,
        state: &DocumentState,
        link: &VersionPrepareLink,
    ) -> Result<(), BridgeError> {
        self.version_prepare_root(state, &link.project)?;
        if !link.epoch_ready(None)? {
            return Err(refused());
        }
        Ok(())
    }
    fn version_prepare_observe(
        &self,
        entry: &Entry,
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        let data = entry.status().map_err(public)?;
        let original = data.original.as_ref().ok_or_else(refused)?;
        let status = self.inner.bridge.edits.release_version_status()?;
        if !status
            .active
            .iter()
            .chain(status.last_terminal.iter())
            .any(|p| {
                p.session_id == original.session_id.as_str()
                    && p.owner_generation == original.owner_generation.as_str()
            })
        {
            return Err(refused());
        }
        Ok(status)
    }
    pub(crate) fn open_agent_version_prepare(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.version_prepare_service()?;
        let entry = service
            .version_edit_requests()
            .preparation(&q)
            .map_err(public)?;
        // Exact retries are observed BEFORE any ordinary root/publication/error tail.
        let Some(call) = entry.begin(Kind::Open, None).map_err(public)? else {
            return self.version_prepare_observe(&entry);
        };
        let result = (|| {
            let (project, stamp) = {
                let state = self.lock();
                self.version_prepare_peers(&state, true)?;
                let project = self.service_project_locked(&state, &entry.scope.saved.runtime_id)?;
                let stamp = self
                    .inner
                    .bridge
                    .edits
                    .saved_registration_guard(&self.inner.session_identity)?
                    .stamp()?;
                (project, stamp)
            };
            service
                .version_prepare_current(&entry, true)
                .map_err(public)?; // OFF Doc/Edit
            let link = self.inner.bridge.edits.version_prepare_link(
                window,
                entry.clone(),
                &service,
                project.clone(),
                VersionPrepareGate {
                    document: Arc::downgrade(&self.inner),
                    stamp,
                },
            )?;
            if let p::Selection::Reserved { reservation_id } = &entry.input.selection {
                // The original lane CAS/take and handoff remain in the existing path.
                return self.edit_reserved_version_with_preparation(
                    &project.runtime_id,
                    reservation_id.as_str(),
                    Some(link),
                );
            }
            let mut ticket = self
                .inner
                .bridge
                .edits
                .release_version_open_ticket(window)?;
            let mut publisher = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let result = (|| {
                let mut state = self.lock();
                self.version_prepare_open_locked(&state, &link, &publisher)?;
                link.claim_open()?;
                link.begin(&publisher, VersionPrepareStep::Open)?;
                let registered = self.registered_edit_root_locked_published(
                    &mut state,
                    crate::edit_protocol::EditDomain::ReleaseVersion,
                    |_| Ok(project.runtime_id.clone()),
                    None,
                    &mut publisher,
                )?;
                link.accepted(&publisher, VersionPrepareStep::Open)?;
                ticket.version_preparation(link)?;
                self.inner.bridge.edits.open_release_version_published(
                    &publisher,
                    window,
                    project.runtime_id,
                    registered,
                    ticket,
                )
            })();
            finish_registration_publisher(publisher);
            result
        })();
        call.finish(result.is_ok()).map_err(public)?;
        result
    }
    pub(crate) fn prepare_agent_version_prepare(
        &self,
        window: &str,
        q: p::Query,
        counters: (u32, u32),
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.version_prepare_service()?;
        let entry = service
            .version_edit_requests()
            .preparation(&q)
            .map_err(public)?;
        let Some(call) = entry.begin(Kind::Prepare, Some(counters)).map_err(public)? else {
            return self.version_prepare_observe(&entry);
        };
        let result = (|| {
            let link = {
                let state = self.lock();
                self.version_prepare_peers(&state, false)?;
                let link = self
                    .inner
                    .bridge
                    .edits
                    .version_prepare_access(window, &entry)?;
                self.version_prepare_current_locked(&state, &link)?;
                link
            };
            service
                .version_prepare_current(&entry, false)
                .map_err(public)?; // OFF Doc/Edit
            let (original, _, _, _) = entry.prepare_data().map_err(public)?;
            self.release_version_phase_admit(
                original.session_id.as_str(),
                crate::edit_owner::ReservedVersionStep::Prepare,
                |b, root, publisher| {
                    b.edits
                        .prepare_agent_version(publisher, window, &link, root)
                },
            )
        })();
        call.finish(result.is_ok()).map_err(public)?;
        result
    }
    pub(super) fn version_prepare_phase_admit<T>(
        &self,
        link: Arc<VersionPrepareLink>,
        step: VersionPrepareStep,
        enqueue: impl FnOnce(
            &DesktopBridge,
            crate::edit_owner::RegisteredEditRoot,
            &RegistrationPublisher,
        ) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        if link.reserved()
            || !matches!(
                step,
                VersionPrepareStep::Prepare | VersionPrepareStep::Apply
            )
        {
            return Err(refused());
        }
        let mut publisher = self
            .inner
            .android_registration_control
            .reserve(RegistrationPublisherKind::General, false)?;
        let result = (|| {
            let mut state = self.lock();
            self.version_prepare_peers(&state, false)?;
            self.version_prepare_root(&state, &link.project)?;
            link.begin(&publisher, step)?;
            let root = self.registered_edit_root_locked_published(
                &mut state,
                crate::edit_protocol::EditDomain::ReleaseVersion,
                |_| Ok(link.project.runtime_id.clone()),
                None,
                &mut publisher,
            )?;
            link.accepted(&publisher, step)?;
            enqueue(&self.inner.bridge, root, &publisher)
        })();
        finish_registration_publisher(publisher);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_main_variants_accept_only_origin_and_bounded_ui_counters() {
        let origin = serde_json::json!({"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)});
        let open = serde_json::json!({"intent":"agent-version-prepare","origin":origin});
        let prepare = serde_json::json!({"intent":"agent-version-prepare","origin":origin,"draftRevision":2,"baselineGeneration":3});
        assert!(open_request(open.clone()).is_ok());
        assert_eq!(prepare_request(prepare.clone()).unwrap().1, (2, 3));
        assert!(
            status_request(serde_json::json!({"intent":"preparation","origin":null}))
                .unwrap()
                .is_none()
        );
        assert!(
            status_request(serde_json::json!({"intent":"preparation","origin":origin}))
                .unwrap()
                .is_some()
        );
        for bad in [
            serde_json::json!({}),
            Value::Null,
            serde_json::json!({"intent":"preparation"}),
        ] {
            assert!(status_request(bad).is_err());
        }
        for field in [
            "path",
            "values",
            "baseline",
            "candidateId",
            "reservationId",
            "window",
            "generation",
        ] {
            let mut a = open.clone();
            a[field] = serde_json::json!("untrusted");
            assert!(open_request(a).is_err());
            let mut a = prepare.clone();
            a[field] = serde_json::json!("untrusted");
            assert!(prepare_request(a).is_err());
        }
        let mut bad = prepare;
        bad["draftRevision"] = serde_json::json!(u32::MAX);
        assert!(prepare_request(bad).is_err());
        let mut bad = open;
        bad["intent"] = serde_json::json!("agent-version-edit");
        assert!(open_request(bad).is_err());
        let duplicate = br#"{"intent":"agent-version-prepare","intent":"agent-version-prepare"}"#;
        assert!(crate::protocol::strict_json(duplicate).is_err());
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
    fn real_document_preopen_future_keeps_payload_and_additional_original_debts() {
        let bridge = Arc::new(DesktopBridge::new(
            "/never-opened-version-preparation-data".into(),
        ));
        let doc = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let mut state = doc.lock();
        let base = lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap();
        let extra_base = installation_memory::additional_document_bytes(&doc, &state).unwrap();
        let edits = bridge.edits.version_prepare_edit_backing().unwrap();
        eprintln!("Version Open/Prepare DATA: document={base}; additional={extra_base}; future={edits}; cap={SESSION_BYTES}");
        assert!(base > 0 && extra_base > 0 && edits > 0);
        assert!(doc.version_prepare_memory(&state).is_ok());
        let observation = credential_format::inspect(
            credential_format::FileKind::AndroidKeystore,
            &[],
            &mut || false,
        )
        .ok()
        .unwrap();
        state.records.push(Record {
            key: RecordKey {
                id: Token("inert-version-prepare-memory".into()),
                revision: 1,
            },
            payload: Arc::new(Payload {
                kind: super::super::Kind::AndroidKeystore,
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
        assert!(doc.version_prepare_memory(&state).is_ok());
        let mut text = "a".repeat(32);
        text.reserve_exact(64 * 1024);
        let capacity = text.capacity();
        let pointer = text.as_ptr();
        state.evidence.phase = evidence_wire::Phase::Refused;
        state.evidence.operation = Some(EvidenceBinding {
            operation_id: 1,
            kind: evidence_wire::OperationKind::Observe,
            selection_id: Some(text),
            epoch: 0,
            purpose: EvidencePurpose::Candidate,
        });
        let extra = installation_memory::additional_document_bytes(&doc, &state).unwrap();
        assert!(extra >= extra_base + capacity);
        assert_eq!(
            lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap(),
            retained
        );
        assert!(doc.version_prepare_memory(&state).is_ok());
        state.evidence.phase = evidence_wire::Phase::Unknown;
        assert!(doc.version_prepare_memory(&state).is_err());
        state.evidence.phase = evidence_wire::Phase::Refused;
        let grow = SESSION_BYTES
            .checked_sub(
                retained
                    .checked_add(extra)
                    .unwrap()
                    .checked_add(edits)
                    .unwrap(),
            )
            .unwrap()
            + 1;
        let payload = Arc::get_mut(&mut state.records[0].payload).unwrap();
        let material = Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
        let MaterialOrigin::Selected(source) = &mut material.origin else {
            panic!("original inert bytes")
        };
        source.bytes.reserve_exact(source.bytes.capacity() + grow);
        let after = lookup_memory::retained_document_bytes(&doc.inner, &state).unwrap();
        assert!(after >= retained + grow);
        assert!(after.checked_add(edits).unwrap() <= SESSION_BYTES); // omitting additional would falsely fit
        assert!(doc.version_prepare_memory(&state).is_err());
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
            pointer
        );
        assert!(after.checked_add(usize::MAX).is_none());
        state.retiring = true;
        assert!(doc.version_prepare_memory(&state).is_err());
    }
}
