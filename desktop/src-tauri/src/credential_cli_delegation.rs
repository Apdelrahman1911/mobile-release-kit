//! Private comparison on the existing vault originals, not another credential
//! owner. Inputs/fields stay in the ordinary native Slot; this proof is weak.
use super::*;

pub(in crate::asset_session) fn native_kind(kind: agent::CredentialKind) -> Kind {
    use agent::CredentialKind as C;
    match kind {
        C::AndroidKeystore => Kind::AndroidKeystore, C::AndroidFirebase => Kind::AndroidFirebase,
        C::AppleP12 => Kind::AppleP12, C::AppleProfile => Kind::AppleProfile, C::AscP8 => Kind::AscP8,
        C::IosFirebase => Kind::IosFirebase, C::GoogleServiceAccount => Kind::GoogleServiceAccount,
        C::ProjectReadToken => Kind::ProjectReadToken, C::AppleReviewContact => Kind::AppleReviewContact,
        C::AppleReviewDemo => Kind::AppleReviewDemo, C::OperationCommitment => Kind::OperationCommitment,
    }
}
pub(in crate::asset_session) fn public_kind(kind: Kind) -> Option<agent::CredentialKind> {
    use agent::CredentialKind as C;
    Some(match kind {
        Kind::AndroidKeystore => C::AndroidKeystore, Kind::AndroidFirebase => C::AndroidFirebase,
        Kind::AppleP12 => C::AppleP12, Kind::AppleProfile => C::AppleProfile, Kind::AscP8 => C::AscP8,
        Kind::IosFirebase => C::IosFirebase, Kind::GoogleServiceAccount => C::GoogleServiceAccount,
        Kind::ProjectReadToken => C::ProjectReadToken, Kind::AppleReviewContact => C::AppleReviewContact,
        Kind::AppleReviewDemo => C::AppleReviewDemo, Kind::OperationCommitment => C::OperationCommitment,
        _ => return None,
    })
}

pub(in crate::asset_session) struct Proof {
    context: Weak<NativeContext>, store: Weak<Mutex<store::StoreBook>>, key: Weak<crypto::VaultKey>,
    kind: Kind, action: Selected,
}
enum Selected {
    Import { owner: Weak<OriginalWork>, payload: Weak<Payload>, token: String, record: format::Id, end: Instant },
    Assess(reuse::Selection),
    Assign { owner: Weak<OriginalWork>, token: String, reference: StoredRef, end: Instant },
}

// No private payload or new durable capability survives in this stamp. The
// exact descriptor witness comes only from the actual NEW/readback publisher.
#[derive(Clone, Copy)]
pub(in crate::asset_session) struct ImportStamp { context: u32, kind: Kind, reference: StoredRef }

// Called only within the original vault's already validated NEW publication.
// This DATA comparison is not, by itself, native or service completion.
pub(in crate::asset_session::vault) fn new_import_stamp(session: &Session, slot: &Slot,
    record: format::Id, row: Option<&Descriptor>) -> Result<ImportStamp, Reason> {
    let row = row.ok_or(Reason::SourceChanged)?;
    let context = slot.context.as_ref().ok_or(Reason::ContextStale)?;
    let kind = slot.kind.ok_or(Reason::SourceChanged)?;
    let identity = session.identity.ok_or(Reason::VaultCorrupt)?;
    if slot.operation != Operation::Commit || slot.target.is_some() || row.authenticated.record != record
        || row.authenticated.descriptor.kind != kind || row.authenticated.revision.counter != 1 || row.mutation_pending
        || session.rows.iter().any(|r| r.authenticated.record == record) { return Err(Reason::SourceChanged); }
    Ok(ImportStamp { context: context.revision, kind, reference: row.reference(identity) })
}


fn refusal() -> AssetError { AssetError::new(Reason::SourceRefused) }
impl Proof {
    pub(in crate::asset_session) fn capture(document: &DocumentBinding, state: &DocumentState,
        selection: &agent::Selection, context_revision: u32, revision: u32) -> Result<Self, AssetError> {
        if state.revision != revision || !selection.valid() { return Err(refusal()); }
        let context = state.context.as_ref().filter(|c| c.revision == context_revision).ok_or_else(refusal)?;
        let session = state.vault.as_ref().filter(|s| s.writable()).ok_or_else(refusal)?;
        let (kind, action) = match selection {
            agent::Selection::CredentialAssessExisting { credential_kind, record_id, expected_revision } => {
                let kind = native_kind(*credential_kind);
                (kind, Selected::Assess(reuse::Selection::capture_credential(state, record_id, *expected_revision, kind)?))
            }
            agent::Selection::CredentialImportPrepared { credential_kind, preview_operation_id, preview_token } => {
                let slot = state.slot.as_ref().filter(|s| s.owner.id == *preview_operation_id).ok_or_else(refusal)?;
                let candidate = slot.candidate.as_ref().ok_or_else(refusal)?;
                (native_kind(*credential_kind), Selected::Import { owner: Arc::downgrade(&slot.owner),
                    payload: Arc::downgrade(&candidate.payload), token: preview_token.clone().into_boxed_str().into_string(),
                    record: format::Id::from_token(&candidate.record_id.0).map_err(|_| refusal())?,
                    end: slot.review_end.ok_or_else(refusal)? })
            }
            agent::Selection::CredentialAssignReviewed { credential_kind, preview_operation_id, preview_token } => {
                let slot = state.slot.as_ref().filter(|s| s.owner.id == *preview_operation_id).ok_or_else(refusal)?;
                (native_kind(*credential_kind), Selected::Assign { owner: Arc::downgrade(&slot.owner),
                    token: preview_token.clone().into_boxed_str().into_string(),
                    reference: slot.vault.reference.ok_or_else(refusal)?, end: slot.review_end.ok_or_else(refusal)? })
            }
            _ => return Err(refusal()),
        };
        let result = Self { context: Arc::downgrade(context), store: Arc::downgrade(&session.store),
            key: Arc::downgrade(session.key.as_ref().ok_or_else(refusal)?), kind, action };
        result.current(document, state)?;
        Ok(result)
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> usize {
        // Existing Seen owns actual live payload bodies. Weak targets still
        // keep their allocation cells after private contents have been dropped.
        std::mem::size_of::<Self>() + 6 * std::mem::size_of::<usize>()
            + std::mem::size_of::<NativeContext>() + std::mem::size_of::<Mutex<store::StoreBook>>()
            + std::mem::size_of::<crypto::VaultKey>() + match &self.action {
                Selected::Assess(s) => s.extra_bytes(),
                Selected::Import { token, .. } => token.capacity() + std::mem::size_of::<OriginalWork>()
                    + std::mem::size_of::<Payload>() + 4 * std::mem::size_of::<usize>(),
                Selected::Assign { token, .. } => token.capacity() + std::mem::size_of::<OriginalWork>()
                    + 2 * std::mem::size_of::<usize>(),
            }
    }
    pub(in crate::asset_session) fn kind(&self) -> agent::Kind {
        match self.action { Selected::Import { .. } => agent::Kind::CredentialImportPrepared,
            Selected::Assess(_) => agent::Kind::CredentialAssessExisting, Selected::Assign { .. } => agent::Kind::CredentialAssignReviewed }
    }
    pub(in crate::asset_session) fn end(&self, now: Instant) -> Instant {
        let cap = now + Duration::from_secs(agent::ALLOW_SECONDS);
        match self.action { Selected::Import { end, .. } | Selected::Assign { end, .. } => cap.min(end), Selected::Assess(_) => cap }
    }
    fn source_identity<'a>(&self, document: &DocumentBinding, state: &'a DocumentState) -> Result<&'a Arc<NativeContext>, AssetError> {
        let context = state.context.as_ref().filter(|c| self.context.as_ptr() == Arc::as_ptr(c)).ok_or_else(refusal)?;
        if context.execution_mode != commands::ExecutionMode::Local || !self.kind.enabled()
            || !document.context_matches(state, context)? { return Err(refusal()); }
        session_kind_gate(context, self.kind)?;
        let session = state.vault.as_ref().filter(|s| !s.revoked && !s.read_only && s.key.is_some()).ok_or_else(refusal)?;
        if self.store.as_ptr() != Arc::as_ptr(&session.store)
            || session.key.as_ref().is_none_or(|k| self.key.as_ptr() != Arc::as_ptr(k))
            || context.registry_generation != session.registry_generation { return Err(refusal()); }
        Ok(context)
    }
    fn source_current<'a>(&self, document: &DocumentBinding, state: &'a DocumentState) -> Result<&'a Arc<NativeContext>, AssetError> {
        let context = self.source_identity(document, state)?;
        if !state.vault.as_ref().is_some_and(Session::writable) { return Err(refusal()); }
        Ok(context)
    }
    pub(in crate::asset_session) fn current(&self, document: &DocumentBinding, state: &DocumentState) -> Result<(), AssetError> {
        let context = self.source_current(document, state)?;
        match &self.action {
            Selected::Assess(s) => s.current(state),
            Selected::Import { owner, payload, token, record, end } => {
                let slot = current_preview(state, context, owner, token, self.kind, Action::Save, *end)?;
                let candidate = slot.candidate.as_ref().ok_or_else(refusal)?;
                let session = state.vault.as_ref().ok_or_else(refusal)?;
                let identity = session.identity.ok_or_else(refusal)?;
                if candidate.existing.is_some() || slot.target.is_some()
                    || payload.as_ptr() != Arc::as_ptr(&candidate.payload) || candidate.payload.kind != self.kind
                    || !candidate.payload.usable_source() || candidate.record_id.0 != record.token()
                    || session.rows.iter().any(|r| r.authenticated.record == *record)
                    || [identity.vault, identity.generation].contains(record) { return Err(refusal()); }
                Ok(())
            }
            Selected::Assign { owner, token, reference, end } => {
                let slot = current_preview(state, context, owner, token, self.kind, Action::Bind, *end)?;
                let key = slot.preview.as_ref().and_then(|p| p.record.as_ref()).ok_or_else(refusal)?;
                if !reference.matches(key) || !usable(state, slot, key, self.kind)
                    || slot.vault.reference.is_none_or(|r| !same_reference(r, *reference)) { return Err(refusal()); }
                Ok(())
            }
        }
    }
    pub(in crate::asset_session) fn attach_prepare(&self, slot: &Slot, link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        match &self.action { Selected::Assess(s) => s.attach(slot, link), _ => Err(refusal()) }
    }
    pub(in crate::asset_session) fn prepared_returned(&self, document: &DocumentBinding, state: &DocumentState,
        link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        self.source_current(document, state)?;
        match &self.action { Selected::Assess(s) => s.returned(state, link), _ => Err(refusal()) }
    }
    pub(in crate::asset_session) fn prepared_view(&self, document: &DocumentBinding, state: &DocumentState,
        link: &Arc<requests::NativeLink>) -> Option<agent::Prepared> {
        self.source_current(document, state).ok()?;
        match &self.action { Selected::Assess(s) => s.view(state, link), _ => None }
    }
    pub(in crate::asset_session) fn import_publication(&self, document: &DocumentBinding, state: &DocumentState,
        slot: &Slot, stamp: ImportStamp) -> Result<ImportStamp, Reason> {
        // Admission/ordinary use still requires Unlocked. Only the original
        // already validated Commit/New publisher runs in Mutating.
        let context = self.source_identity(document, state).map_err(|e| e.reason)?;
        if !state.vault.as_ref().is_some_and(|s| s.state == State::Mutating) { return Err(Reason::SourceChanged); }
        let Selected::Import { record: selected, .. } = self.action else { return Err(Reason::SourceRefused); };
        if slot.operation != Operation::Commit || slot.target.is_some() || slot.kind != Some(self.kind)
            || stamp.reference.record != selected || stamp.kind != self.kind || stamp.context != context.revision
            || slot.context.as_ref().is_none_or(|c| !Arc::ptr_eq(c, context)) {
            return Err(Reason::SourceChanged);
        }
        Ok(stamp)
    }
    pub(in crate::asset_session) fn completion(&self, document: &DocumentBinding, state: &DocumentState, slot: &Slot)
        -> Option<(agent::State, agent::Reason, Option<agent::KeyReference>)> {
        if matches!(self.action, Selected::Assess(_)) {
            return crate::asset_session::agent_upload_key::prepare_completion(document, state, slot);
        }
        if !matches!(slot.operation, Operation::Commit | Operation::Bind) || !slot.owner.resources_settled()
            || !reuse::normal_returns(&slot.owner) || slot.phase != Phase::Idle || slot.settlement != Settlement::Known { return None; }
        if slot.reason != Reason::None || slot.error.is_some() || slot.cleanup_end.is_some() || slot.owner.stopped() {
            return Some(match slot.reason {
                Reason::UserCancelled | Reason::Shutdown => (agent::State::Cancelled, agent::Reason::PermissionRevoked, None),
                Reason::Deadline => (agent::State::Cancelled, agent::Reason::Expired, None),
                _ => (agent::State::RecoveryRequired, agent::Reason::RecoveryRequired, None),
            });
        }
        let context = self.source_current(document, state).ok()?;
        let session = state.vault.as_ref()?;
        match &self.action {
            Selected::Import { record, .. } => {
                let stamp = slot.vault.credential_import?;
                if slot.operation != Operation::Commit || stamp.context != context.revision || stamp.kind != self.kind
                    || stamp.reference.record != *record || stamp.reference.revision.counter != 1
                    || session.identity != Some(stamp.reference.identity) || slot.kind != Some(self.kind)
                    || !slot.result_record.as_ref().is_some_and(|k| stamp.reference.matches(k))
                    || slot.vault.outcome != Some(store::StorageOutcome { effect:store::Effect::KnownApplied,
                        durability:store::Durability::Confirmed, cleanup:store::Cleanup::Known })
                    || !slot.owner.vault.try_lock().is_ok_and(|w| w.key.is_none() && w.first.is_none()) { return None; }
                let key = reference(KeyReference::native(stamp.reference.identity, stamp.reference.record, stamp.reference.revision))?;
                Some((agent::State::ImportedUnassigned, agent::Reason::None, Some(key)))
            }
            Selected::Assign { reference: expected, .. } => {
                if slot.operation != Operation::Bind || slot.kind != Some(self.kind) { return None; }
                let loan = session.bound.iter().flatten().find(|loan| loan.payload.kind == self.kind
                    && same_reference(loan.reference, *expected) && Arc::ptr_eq(&loan.context, context)
                    && loan.current(state, session))?;
                let key = reference(KeyReference::native(loan.reference.identity, loan.reference.record, loan.reference.revision))?;
                Some((agent::State::Assigned, agent::Reason::None, Some(key)))
            }
            Selected::Assess(_) => None,
        }
    }
    #[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
    pub(in crate::asset_session) fn run(&self, document: &DocumentBinding, link: Arc<requests::NativeLink>) -> Result<Option<u32>, AssetError> {
        match &self.action {
            Selected::Import { token, .. } => document.commit_vault_delegated(token, Some(link)).map(|_| None),
            Selected::Assess(s) => s.run(document, link).map(Some),
            Selected::Assign { token, .. } => document.bind_vault_delegated(token, Some(link)).map(|_| None),
        }
    }
    #[cfg(not(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper"))))]
    pub(in crate::asset_session) fn run(&self, _document: &DocumentBinding, _link: Arc<requests::NativeLink>) -> Result<Option<u32>, AssetError> {
        Err(AssetError::new(Reason::Unqualified))
    }
}

fn current_preview<'a>(state: &'a DocumentState, context: &Arc<NativeContext>, owner: &Weak<OriginalWork>,
    token: &str, kind: Kind, action: Action, end: Instant) -> Result<&'a Slot, AssetError> {
    let slot = state.slot.as_ref().filter(|s| owner.as_ptr() == Arc::as_ptr(&s.owner)).ok_or_else(refusal)?;
    let preview = slot.preview.as_ref().filter(|p| p.token.0 == token && p.action == action).ok_or_else(refusal)?;
    if slot.phase != Phase::Preview || slot.settlement != Settlement::Known || slot.reason != Reason::None
        || slot.error.is_some() || slot.cleanup_end.is_some() || slot.owner.stopped() || slot.kind != Some(kind)
        || slot.review_end != Some(end) || Instant::now() >= end || !slot.owner.resources_settled()
        || !reuse::normal_returns(&slot.owner) || !preview_subject_valid(state, slot, preview)
        || slot.context.as_ref().is_none_or(|c| !Arc::ptr_eq(c, context))
        || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits) { return Err(refusal()); }
    Ok(slot)
}

#[cfg(all(test,debug_assertions))]
mod tests {
    use super::*;
    #[test]
    fn ordinary_credential_weak_quote_preserves_actual_document_and_payload_charges() {
        // Weak empty controls are DATA for the actual pre-admission quote, not
        // a captured Preview, authenticated descriptor or native return.
        let proof=Proof { context:Weak::new(),store:Weak::new(),key:Weak::new(),kind:Kind::AppleP12,
            action:Selected::Import {owner:Weak::new(),payload:Weak::new(),token:"a".repeat(32),
                record:format::Id::from_bytes([1;16]).unwrap(),end:Instant::now()+REVIEW} };
        let bridge=Arc::new(DesktopBridge::new("/never-opened-general-credential-census".into()));
        let document=DocumentBinding::new(bridge.clone());bridge.edits.initial_document("main").unwrap();
        let mut state=document.lock();
        let base=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
        let extra_base=installation_memory::additional_document_bytes(&document,&state).unwrap();
        for (name,kind,file,capacity) in [("inert-p12",Kind::AppleP12,credential_format::FileKind::AppleP12,4*1024*1024),
            ("inert-p8",Kind::AscP8,credential_format::FileKind::AscP8,16*1024)] {
            let observation=credential_format::inspect(file,&[],&mut||false).ok().expect("inert empty file observation");
            state.records.push(Record {key:RecordKey {id:Token(name.into()),revision:1},payload:Arc::new(Payload {kind,fields:None,
                material:Some(Arc::new(Material {origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(Vec::with_capacity(capacity))),observation}))}),mutation_pending:false});
        }
        let retained=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
        // Actual comparison allocation outside the lookup census. This is no
        // evidence observation, saved-input admission or private receipt.
        let mut selection_id="a".repeat(32);selection_id.reserve_exact(64*1024);
        let selection_capacity=selection_id.capacity();let selection_pointer=selection_id.as_ptr();
        state.evidence.phase=evidence_wire::Phase::Refused;
        state.evidence.operation=Some(EvidenceBinding {operation_id:1,kind:evidence_wire::OperationKind::Observe,
            selection_id:Some(selection_id),epoch:0,purpose:EvidencePurpose::Candidate});
        let additional=installation_memory::additional_document_bytes(&document,&state).unwrap();
        let extra=crate::asset_session::agent_upload_key::grant_allocation_bytes(proof.retained_bytes(),"inert-project".len(),"/never-opened-general-credential-census".len()).unwrap();
        let total=retained.checked_add(additional).unwrap().checked_add(extra).unwrap();
        eprintln!("credential CLI DATA census: base={base}; base_additional={extra_base}; retained={retained}; additional={additional}; evidence_capacity={selection_capacity}; weak_grant={extra}; total={total}; cap={SESSION_BYTES}");
        assert!(retained>=base+4*1024*1024+16*1024+2*RECORD_METADATA_BYTES);
        assert!(extra_base>0 && additional>=extra_base+selection_capacity);
        assert_eq!(lookup_memory::retained_document_bytes(&document.inner,&state).unwrap(),retained);
        assert_eq!(crate::asset_session::agent_upload_key::allow_backing_bytes(&document,&state,extra).unwrap(),total);
        assert!(total<SESSION_BYTES); // Actual compiled layout, never assumed from a flat allowance.
        assert!(crate::asset_session::agent_upload_key::grant_allocation_bytes(usize::MAX,0,0).is_none());
        assert!(crate::asset_session::agent_upload_key::allow_backing_bytes(&document,&state,usize::MAX).is_err());
        assert!(proof.current(&document,&state).is_err()); // No authority/receipt was constructed.
        state.evidence.phase=evidence_wire::Phase::Unknown;
        assert!(crate::asset_session::agent_upload_key::allow_backing_bytes(&document,&state,extra).is_err());
        state.evidence.phase=evidence_wire::Phase::Refused;
        assert_eq!(state.evidence.operation.as_ref().unwrap().selection_id.as_ref().unwrap().as_ptr(),selection_pointer);
        let grow=SESSION_BYTES.checked_sub(total).unwrap()+1;
        let payload=Arc::get_mut(&mut state.records[0].payload).unwrap();
        let material=Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
        let MaterialOrigin::Selected(source)=&mut material.origin else {panic!("original inert source")};
        source.bytes.reserve_exact(source.bytes.capacity().checked_add(grow).unwrap());
        assert!(crate::asset_session::agent_upload_key::allow_backing_bytes(&document,&state,extra).is_err());
        state.retiring=true;assert!(crate::asset_session::agent_upload_key::allow_backing_bytes(&document,&state,extra).is_err());
    }
}
