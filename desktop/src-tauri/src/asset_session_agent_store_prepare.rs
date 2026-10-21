//! Main-only, two separately approved phases on the SAME Saved Store owner.
//! Picked/assigned material is always borrowed from the actual Document. CLI
//! IDs and inventory summaries cannot create a material loan or a Prepared.
use super::*;
use crate::{
    saved_command_owner::AgentStorePreparationInput as Input,
    service_store_prepare_protocol as flow, service_store_requests::preparation as queue,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AllowPrepare {
    kind: flow::Kind,
    prepare: serde_json::Value,
    consent_version: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AllowStart {
    origin: flow::Query,
    review: flow::Review,
    consent_version: String,
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len() > flow::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json_with_limits(bytes, flow::RAW_NODES, flow::RAW_DEPTH)
        .map_err(|_| BridgeError::invalid())?;
    crate::protocol::check_value(&value).map_err(|_| BridgeError::invalid())?;
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
struct Pins {
    context: Weak<NativeContext>,
    primary: Weak<Payload>,
    second: Option<Weak<Payload>>,
}
impl Pins {
    fn capture(m: &Arc<SelectedStoreMaterial>, paired: bool) -> Result<Self, BridgeError> {
        let (c, p) = m.census_parts();
        let mut rest = m.supplemental_census();
        let second = rest.next().map(|(_, p)| Arc::downgrade(p));
        if rest.next().is_some() || second.is_some() != paired {
            return Err(public(Error::Conflict));
        }
        Ok(Self {
            context: Arc::downgrade(c),
            primary: Arc::downgrade(p),
            second,
        })
    }
    fn matches(&self, m: &Arc<SelectedStoreMaterial>) -> bool {
        let (c, p) = m.census_parts();
        let mut rest = m.supplemental_census();
        self.context.as_ptr() == Arc::as_ptr(c)
            && self.primary.as_ptr() == Arc::as_ptr(p)
            && match (&self.second, rest.next()) {
                (None, None) => true,
                (Some(a), Some((_, b))) => a.as_ptr() == Arc::as_ptr(b),
                _ => false,
            }
            && rest.next().is_none()
    }
}
pub(in crate::asset_session) struct Grant {
    pub(in crate::asset_session::agent_store) scope: Arc<queue::Scope>,
    input: Input,
    native: NativeProject,
    stamp: SavedEditStamp,
    pins: Pins,
    _witness: Arc<()>,
}
impl DocumentBinding {
    fn preparation_owner(&self, kind: flow::Kind) -> &SavedCommandOwner {
        self.store_delegate_owner(if kind.candidate() {
            p::Kind::CandidatePrepare
        } else {
            p::Kind::AccessCheck
        })
    }
    fn preparation_gate(
        &self,
        s: &DocumentState,
        kind: flow::Kind,
    ) -> crate::local_store_preflight_protocol::Availability {
        self.store_delegate_gate(
            s,
            if kind.candidate() {
                p::Kind::CandidatePrepare
            } else {
                p::Kind::AccessCheck
            },
        )
    }
    fn preparation_material(
        &self,
        s: &DocumentState,
        input: &Input,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        match input {
            Input::Access(c) => self.review_store_preflight_material(s, c, registration, root),
            Input::Candidate(c) => self.review_store_prepare_material(s, c, registration, root),
        }
    }
    fn preparation_budget(
        &self,
        s: &DocumentState,
        input: &Input,
        m: &Arc<SelectedStoreMaterial>,
    ) -> Result<(), BridgeError> {
        match input {
            Input::Access(_) => self.store_preflight_budget(s, m),
            Input::Candidate(_) => self.store_prepare_budget(s, m),
        }
    }
    fn preparation_current(
        &self,
        s: &DocumentState,
        g: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(s)?;
        if !edit.matches(&g.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(g.native.input_revision)
            || g.native.registration_generation != registration
            || g.native.canonical_root != root.path
            || !root
                .identity
                .posix()
                .is_ok_and(|p| p.service_identity() == (g.native.device, g.native.inode))
            || !Arc::ptr_eq(&g.native.document_identity, &self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    pub(crate) fn agent_store_preparation_access(
        &self,
        window: &str,
    ) -> Result<flow::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.agent_store_service()? {
            Some(s) => s.store_requests().preparation_access().map_err(public),
            None => Ok(flow::Access::empty()),
        }
    }
    pub(crate) fn revoke_agent_store_preparation(
        &self,
        window: &str,
    ) -> Result<flow::Access, BridgeError> {
        self.revoke_agent_store(window)?; // SAME revoke epoch and all original controls.
        self.agent_store_preparation_access(window)
    }
    pub(crate) fn allow_agent_store_prepare(
        &self,
        window: &str,
        args: AllowPrepare,
    ) -> Result<flow::Access, BridgeError> {
        if window != MAIN || args.consent_version != flow::PREPARE_CONSENT {
            return Err(BridgeError::invalid());
        }
        let input = Input::parse(args.kind, &args.prepare)?;
        let selection = input.selection()?;
        let at = Instant::now();
        let (native, stamp, pins, epoch) = {
            let mut s = self.lock();
            self.service_document_gate(&s)?;
            if s.agent_store_grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
                || s.agent_store_preparation
                    .as_ref()
                    .is_some_and(|g| g.scope.occupied())
                || self.preparation_gate(&s, args.kind)
                    != crate::local_store_preflight_protocol::Availability::Available
            {
                return Err(public(Error::Busy));
            }
            self.preparation_owner(args.kind).ensure_idle()?;
            let (registration, root) = self
                .registry_result(
                    &mut s,
                    self.inner.bridge.native_project(input.project()),
                    None,
                )
                .map_err(|_| public(Error::Conflict))?;
            let material = self.preparation_material(&s, &input, registration, &root)?;
            self.preparation_budget(&s, &input, &material)?;
            let pins = Pins::capture(&material, args.kind == flow::Kind::PairedVersions)?;
            let native = self.service_project_locked(&s, input.project())?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let epoch = self.inner.agent_store_revoke_epoch.load(Ordering::Acquire);
            if epoch == u64::MAX {
                return Err(public(Error::StateUnknown));
            }
            (native, edit.stamp()?, pins, epoch)
        };
        // The original Host and READ query are OFF Doc/Edit/Saved locks.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service.store_point(&native.runtime_id).map_err(public)?;
        let witness = Arc::new(()); // Comparison identity only, not a Prepared/native receipt.
        let expires = at
            .checked_add(std::time::Duration::from_millis(p::INTENT_MS))
            .ok_or_else(|| public(Error::StateUnknown))?;
        let scope = queue::Scope::new(
            point.saved.project_id.clone(),
            native.runtime_id.clone(),
            Id::random().map_err(public)?,
            selection,
            native.canonical_root.clone(),
            native.device,
            native.inode,
            point.saved.revision,
            expires,
            point.read,
            Arc::downgrade(&self.inner.session_identity),
            Arc::downgrade(&witness),
            self.inner.changes.clone(),
        );
        if !scope.matches(&point.saved) {
            return Err(public(Error::Conflict));
        }
        let id = Id::random().map_err(public)?;
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            input,
            native,
            stamp,
            pins,
            _witness: witness,
        });
        let mut s = self.lock();
        if self.inner.agent_store_revoke_epoch.load(Ordering::Acquire) != epoch
            || s.agent_store_grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
            || s.agent_store_preparation
                .as_ref()
                .is_some_and(|g| g.scope.occupied())
            || self.preparation_gate(&s, args.kind)
                != crate::local_store_preflight_protocol::Availability::Available
        {
            return Err(public(Error::Busy));
        }
        let (registration, root) = self
            .registry_result(
                &mut s,
                self.inner.bridge.native_project(grant.input.project()),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.preparation_current(&s, &grant, &edit, registration, &root)?;
        let m = self.preparation_material(&s, &grant.input, registration, &root)?;
        if !grant.pins.matches(&m) {
            return Err(public(Error::Conflict));
        }
        self.preparation_budget(&s, &grant.input, &m)?;
        self.preparation_owner(args.kind).ensure_idle()?;
        service.store_requests().can_allow().map_err(public)?;
        if let Some(old) = self.inner.agent_store_service.get() {
            if old.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_store_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        s.agent_store_preparation = Some(grant);
        match service
            .store_requests()
            .allow_preparation(scope.clone(), id)
        {
            Ok(v) => Ok(v),
            Err(e) => {
                scope
                    .control
                    .stop(p::Reason::PermissionRevoked, Instant::now());
                Err(public(e))
            }
        }
    }
    pub(crate) fn allow_agent_store_preparation_start(
        &self,
        window: &str,
        args: AllowStart,
    ) -> Result<flow::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self
            .agent_store_service()?
            .ok_or_else(|| public(Error::Unavailable))?;
        let entry = service
            .store_requests()
            .preparation_entry(&args.origin)
            .map_err(public)?;
        if args.consent_version != entry.scope.selection.kind.consent()
            || entry.installed_review().map_err(public)? != args.review
        {
            return Err(BridgeError::invalid());
        }
        // Joined native Prepared is required; no supplied status can recreate it.
        let point = service
            .store_point(&entry.scope.runtime_id)
            .map_err(public)?;
        if !entry.scope.matches(&point.saved) || !Arc::ptr_eq(&entry.scope.read, &point.read) {
            return Err(public(Error::Conflict));
        }
        let id = Id::random().map_err(public)?;
        let mut s = self.lock();
        let g = s
            .agent_store_preparation
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, &entry.scope))
            .cloned()
            .ok_or_else(|| public(Error::Conflict))?;
        let (registration, root) = self
            .registry_result(
                &mut s,
                self.inner.bridge.native_project(&g.native.runtime_id),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.preparation_current(&s, &g, &edit, registration, &root)?;
        if self.preparation_gate(&s, g.scope.selection.kind)
            != crate::local_store_preflight_protocol::Availability::Available
        {
            return Err(public(Error::Busy));
        }
        let m = self
            .preparation_owner(g.scope.selection.kind)
            .store_preparation_current(&entry, &args.review)?;
        self.recheck_preparation(&s, &g, &m, registration, &root)?;
        self.preparation_budget(&s, &g.input, &m)?;
        entry.allow_start(&args.review, id).map_err(public)?;
        service
            .store_requests()
            .preparation_access()
            .map_err(public)
    }
    fn recheck_preparation(
        &self,
        s: &DocumentState,
        g: &Grant,
        m: &Arc<SelectedStoreMaterial>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        if !g.pins.matches(m) {
            return Err(public(Error::Conflict));
        }
        match &g.input {
            Input::Access(_) => self.recheck_store_preflight_material(s, m, registration, root),
            Input::Candidate(_) => self.recheck_store_prepare_material(s, m, registration, root),
        }
    }
    fn admit_store_preparation(
        &self,
        service: &Arc<ApplicationService>,
        claim: &queue::PrepareClaim,
    ) -> Result<(), BridgeError> {
        let entry = &claim.entry;
        let g = {
            self.lock()
                .agent_store_preparation
                .as_ref()
                .filter(|g| Arc::ptr_eq(&g.scope, &entry.scope))
                .cloned()
                .ok_or_else(|| public(Error::Conflict))?
        };
        entry.current(false).map_err(public)?;
        let current = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&g.native)
            .map_err(public)?;
        if !Arc::ptr_eq(&current, service) {
            return Err(public(Error::Conflict));
        }
        match claim.call {
            queue::Call::Prepare => {
                let point = service.store_point(&g.native.runtime_id).map_err(public)?;
                if !entry.scope.matches(&point.saved)
                    || !Arc::ptr_eq(&entry.scope.read, &point.read)
                {
                    return Err(public(Error::Conflict));
                }
            }
            queue::Call::Start => service
                .consume_store_preparation_observation(&entry.scope)
                .map_err(public)?,
        }
        let mut s = self.lock();
        if s.agent_store_preparation
            .as_ref()
            .is_none_or(|held| !Arc::ptr_eq(held, &g))
        {
            return Err(public(Error::Conflict));
        }
        let (registration, root) = self
            .registry_result(
                &mut s,
                self.inner.bridge.native_project(&g.native.runtime_id),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.preparation_current(&s, &g, &edit, registration, &root)?;
        let gate = self.preparation_gate(&s, g.scope.selection.kind);
        if gate != crate::local_store_preflight_protocol::Availability::Available {
            return Err(public(Error::Busy));
        }
        let owner = self.preparation_owner(g.scope.selection.kind);
        let m = match claim.call {
            queue::Call::Prepare => self.preparation_material(&s, &g.input, registration, &root)?,
            queue::Call::Start => owner
                .store_preparation_current(entry, &entry.installed_review().map_err(public)?)?,
        };
        self.recheck_preparation(&s, &g, &m, registration, &root)?;
        self.preparation_budget(&s, &g.input, &m)?;
        match claim.call {
            queue::Call::Prepare => owner.prepare_agent_store_original(
                &g.input,
                entry.clone(),
                registration,
                root,
                gate,
                m,
            ),
            queue::Call::Start => {
                let admitted =
                    owner.start_agent_store_original(entry, Some((registration, root)), gate, m)?;
                drop(edit);
                drop(s);
                admitted.release();
                Ok(())
            }
        }
    }
    pub(in crate::asset_session::agent_store) fn stop_preparation_grant(
        &self,
        g: &Grant,
        reason: p::Reason,
        at: Instant,
    ) {
        g.scope.control.stop(reason, at);
        if let Some(entry) = g.scope.original() {
            if entry.constructed() {
                self.preparation_owner(g.scope.selection.kind)
                    .stop_store_preparation(&entry, reason, at);
            }
        }
    }
    pub(in crate::asset_session::agent_store) fn check_store_preparation(&self) {
        let mut s = self.lock();
        let Some(g) = s.agent_store_preparation.as_ref().cloned() else {
            return;
        };
        if g.scope.original().is_some_and(|e| !e.needs_original()) {
            return;
        }
        let checked = (|| {
            let (registration, root) = self
                .registry_result(
                    &mut s,
                    self.inner.bridge.native_project(&g.native.runtime_id),
                    None,
                )
                .map_err(|_| public(Error::Conflict))?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.preparation_current(&s, &g, &edit, registration, &root)?;
            let m = self.preparation_material(&s, &g.input, registration, &root)?;
            if !g.pins.matches(&m) {
                return Err(public(Error::Conflict));
            }
            Ok(())
        })();
        if checked.is_err() {
            self.stop_preparation_grant(&g, p::Reason::ContextChanged, Instant::now());
        }
    }
    pub(in crate::asset_session::agent_store) fn tick_store_preparation(
        &self,
        service: &Arc<ApplicationService>,
    ) {
        match service.store_requests().claim_preparation() {
            Ok(Some(claim)) => {
                let result = self.admit_store_preparation(service, &claim);
                if result.is_err() {
                    let s = self.lock();
                    if let Some(g) = s
                        .agent_store_preparation
                        .as_ref()
                        .filter(|g| Arc::ptr_eq(&g.scope, &claim.entry.scope))
                    {
                        self.stop_preparation_grant(g, p::Reason::NativeRefused, Instant::now());
                    } else {
                        claim.entry.unknown(p::Reason::CleanupUnknown);
                    }
                }
                claim.returned(result.is_ok()); // Real same relay call, not native finality.
            }
            Ok(None) => (),
            Err(_) => service.store_requests().fence(),
        }
    }
}
pub(in crate::asset_session::agent_store) fn flush_preparation(
    service: &ApplicationService,
) -> Result<(), Error> {
    for entry in service.store_requests().preparation_entries()? {
        let Some(history) = entry.claim_history()? else {
            continue;
        };
        let n = &history.data;
        let result = if history.first {
            service.begin_operation(
                &entry.scope.runtime_id,
                n.operation.operation_id.clone(),
                entry.scope.selection.kind.action(),
                n.state,
                n.settlement(),
            )
        } else {
            service.publish_operation(
                &entry.scope.runtime_id,
                n.operation.operation_id.clone(),
                entry.scope.selection.kind.action(),
                n.state,
                n.settlement(),
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
    fn store_preparation_raw_uses_original_closed_input_and_bounded_nodes() {
        use flow::Kind::*;
        // The real main-window bridge must admit exactly these fixed commands;
        // registering generate_handler alone does not grant a Tauri capability.
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
        assert_eq!(capability["windows"], serde_json::json!(["main"]));
        assert_eq!(capability["local"], true);
        let permissions = capability["permissions"].as_array().unwrap();
        for command in [
            "agent_store_preparation_access",
            "revoke_agent_store_preparation",
            "allow_agent_store_prepare",
            "allow_agent_store_preparation_start",
        ] {
            assert!(include_str!("../build.rs").contains(&format!("\"{command}\"")));
            let permission = format!("allow-{}", command.replace('_', "-"));
            assert_eq!(
                permissions
                    .iter()
                    .filter(|p| p.as_str() == Some(permission.as_str()))
                    .count(),
                1
            );
        }
        for kind in [
            AndroidAccess,
            IosAccess,
            AndroidCandidate,
            IosCandidate,
            AndroidVersions,
            IosVersions,
            PairedVersions,
        ] {
            let mut prepare = if kind.candidate() {
                serde_json::to_value(crate::local_store_prepare_protocol::tests::context()).unwrap()
            } else {
                serde_json::to_value(crate::local_store_preflight_protocol::tests::context())
                    .unwrap()
            };
            prepare.as_object_mut().unwrap().remove("operation");
            // Original ordinary Android request omits platform; its returned
            // Context includes it. Do not widen the original request grammar.
            match kind {
                AndroidAccess | AndroidCandidate => {
                    prepare.as_object_mut().unwrap().remove("platform");
                }
                IosAccess => {
                    prepare["platform"] = "ios".into();
                }
                IosCandidate => {
                    prepare["platform"] = "ios".into();
                    prepare["confirmation"] = "candidate:ios:1.2.3:42".into();
                }
                AndroidVersions => {
                    prepare["query"] = "android-current-versions".into();
                }
                IosVersions => {
                    prepare["platform"] = "ios".into();
                    prepare["query"] = "ios-current-versions".into();
                }
                PairedVersions => {
                    prepare["platform"] = "both".into();
                    prepare["query"] = "paired-current-versions".into();
                    prepare["iosRecord"] =
                        serde_json::json!({"recordId":"d".repeat(32),"recordRevision":2});
                }
            }
            let raw=serde_json::to_vec(&serde_json::json!({"kind":kind,"prepare":prepare,"consentVersion":flow::PREPARE_CONSENT})).unwrap();
            let input: AllowPrepare = decode(&raw).unwrap();
            assert_eq!(
                Input::parse(input.kind, &input.prepare)
                    .unwrap()
                    .selection()
                    .unwrap()
                    .kind,
                kind
            );
        }
        // Rejected before Document/native selection. No hidden full Value
        // tree or arbitrary private fields may outgrow this same RAW quote.
        let excessive=serde_json::to_vec(&serde_json::json!({"kind":"android-access","consentVersion":flow::PREPARE_CONSENT,"prepare":vec![0;flow::RAW_NODES+1]})).unwrap();
        assert!(excessive.len() < flow::RAW_LIMIT);
        assert!(decode::<AllowPrepare>(&excessive).is_err());
        assert!(
            decode::<AllowPrepare>(b"{\"kind\":\"android-access\",\"kind\":\"ios-access\"}")
                .is_err()
        );
    }
    #[test]
    fn store_preparation_native_grant_and_input_fit_existing_fixed_backing() {
        use std::mem::size_of;
        // Old and new grant cells may coexist. Original material descendants
        // remain in the unchanged native Document/Store census, never here as
        // omitted loans. Both extra records are weak identities only.
        let cells = size_of::<Grant>()
            + size_of::<super::super::Grant>()
            + size_of::<Input>()
            + size_of::<Pins>()
            + size_of::<queue::Scope>();
        // Fixed bounded roots plus copied small context/publication records for
        // both grants; no payload is owned by these weak identity records.
        let heaps = 8 * 4096 + 16 * 1024;
        // The remaining 32KiB of the SAME 128KiB fixed term is tested in
        // the actual Saved binding fixture; it is not a second reservation.
        assert!(cells + heaps <= 96 * 1024, "{cells}+{heaps}");
        assert!(size_of::<serde_json::Value>() <= 512);
        assert_eq!(flow::RAW_NODES, 128);
        assert_eq!(flow::RAW_DEPTH, 8);
        assert_eq!(p::DOCUMENT_BACKING, 2 * 1024 * 1024);
    }
}
