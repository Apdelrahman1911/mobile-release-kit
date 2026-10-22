//! Fixed stored Android-key selection. No payload, SourceBook or native result
//! can be constructed from this comparison. Load/assessment stays the original
//! vault Job; the compact reply is recorded only by its real Prepared waiter.
use super::*;
use std::sync::OnceLock;
use crate::service_protocol::Id;

pub(super) struct Selection {
    reference: StoredRef,
    kind: Kind,
    original: OnceLock<Weak<OriginalWork>>,
    reply: OnceLock<Reply>,
}
struct Reply {
    operation: u32,
    revision: u32,
    context: u32,
    token: Id,
    end: Instant,
}
impl Selection {
    pub(super) fn capture(state: &DocumentState, record: &Id, revision: u32) -> Result<Self, AssetError> {
        Self::capture_kind(state, record, revision, Kind::AndroidKeystore)
    }
    pub(super) fn capture_credential(state: &DocumentState, record: &Id, revision: u32, kind: Kind) -> Result<Self, AssetError> {
        if !credential::public_kind(kind).is_some_and(|kind| kind.general_assessment()) { return Err(AssetError::invalid()); }
        Self::capture_kind(state, record, revision, kind)
    }
    fn capture_kind(state: &DocumentState, record: &Id, revision: u32, kind: Kind) -> Result<Self, AssetError> {
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let key = own_record(commands::RecordRef { record_id: record.as_str(), expected_revision: revision })?;
        let row = session.row(&key).filter(|row| !row.mutation_pending
            && row.authenticated.descriptor.kind == kind).ok_or_else(AssetError::invalid)?;
        Ok(Self { reference: row.reference(session.identity.ok_or_else(AssetError::invalid)?), kind,
            original: OnceLock::new(), reply: OnceLock::new() })
    }
    fn delegate_kind(&self) -> agent::Kind {
        if self.kind == Kind::AndroidKeystore { agent::Kind::PrepareExisting } else { agent::Kind::CredentialAssessExisting }
    }
    pub(super) fn extra_bytes(&self) -> usize {
        // The future Weak keeps the original allocation body alive; quote it
        // BEFORE attachment. Reply is inline, its one token is exactly32 bytes.
        2 * std::mem::size_of::<usize>() + std::mem::size_of::<OriginalWork>() + 32
    }
    fn source(&self, state: &DocumentState) -> Result<(), AssetError> {
        let context = state.context.as_ref().ok_or_else(AssetError::invalid)?;
        let session = state.vault.as_ref().filter(|s| s.writable()).ok_or_else(AssetError::invalid)?;
        session_kind_gate(context, self.kind)?;
        if session.identity != Some(self.reference.identity)
            || context.registry_generation != session.registry_generation
            || !session.rows.iter().any(|r| !r.mutation_pending
                && r.authenticated.descriptor.kind == self.kind
                && same_reference(r.reference(self.reference.identity), self.reference)) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        Ok(())
    }
    pub(super) fn current(&self, state: &DocumentState) -> Result<(), AssetError> {
        idle(state)?;
        self.source(state)?;
        if self.original.get().is_some() || self.reply.get().is_some() { return Err(AssetError::invalid()); }
        Ok(())
    }
    pub(super) fn attach(&self, slot: &Slot, link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        if slot.operation != Operation::Prepare || slot.kind != Some(self.kind)
            || !slot.vault.reference.is_some_and(|r| same_reference(r, self.reference))
            || !slot.owner.agent_upload_key.get().is_some_and(|actual| Arc::ptr_eq(actual, link))
            || link.entry().scope().kind != self.delegate_kind() {
            return Err(AssetError::invalid());
        }
        self.original.set(Arc::downgrade(&slot.owner)).map_err(|_| AssetError::invalid())
    }
    fn loaded<'a>(&self, state: &'a DocumentState, link: &Arc<requests::NativeLink>) -> Result<(&'a Slot, &'a Preview, Instant), AssetError> {
        self.source(state)?;
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        let context = state.context.as_ref().ok_or_else(AssetError::invalid)?;
        let end = slot.review_end.ok_or_else(AssetError::invalid)?;
        let preview = slot.preview.as_ref().ok_or_else(AssetError::invalid)?;
        let key = preview.record.as_ref().ok_or_else(AssetError::invalid)?;
        if !self.original.get().is_some_and(|o| o.as_ptr() == Arc::as_ptr(&slot.owner))
            || !slot.owner.agent_upload_key.get().is_some_and(|l| Arc::ptr_eq(l, link))
            || link.entry().scope().kind != self.delegate_kind()
            || slot.context.as_ref().is_none_or(|c| !Arc::ptr_eq(c, context))
            || slot.operation != Operation::Prepare || slot.kind != Some(self.kind)
            || slot.phase != Phase::Preview || slot.settlement != Settlement::Known
            || slot.reason != Reason::None || slot.error.is_some() || slot.cleanup_end.is_some()
            || slot.owner.stopped() || !slot.owner.ended.load(Ordering::SeqCst)
            || !slot.owner.resources_settled() || !normal_returns(&slot.owner)
            || end > link.entry().scope().end || Instant::now() >= end
            || preview.action != Action::Bind || !self.reference.matches(key)
            || !preview_subject_valid(state, slot, preview) || !usable(state, slot, key, self.kind)
            || !slot.vault.reference.is_some_and(|r| same_reference(r, self.reference))
            || !slot.vault.loaded.as_ref().is_some_and(|p| p.kind == self.kind
                && if self.kind.file().is_some() { p.material.as_ref().is_some_and(|m| matches!(&m.origin,
                    MaterialOrigin::Stored(s) if same_reference(s.reference, self.reference))) }
                else { p.material.is_none() && p.fields.is_some() })
            || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits) {
            return Err(AssetError::new(Reason::SourceRefused));
        }
        Ok((slot, preview, end))
    }
    pub(super) fn returned(&self, state: &DocumentState, link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        link.current().map_err(|_| AssetError::new(Reason::UserCancelled))?;
        let (slot, preview, end) = self.loaded(state, link)?;
        if !link.entry().needs_native_retirement(slot.owner.id).map_err(|_| AssetError::invalid())? {
            return Err(AssetError::invalid());
        }
        let reply = Reply { operation: slot.owner.id, revision: state.revision,
            context: slot.context.as_ref().ok_or_else(AssetError::invalid)?.revision,
            token: Id::parse(&preview.token.0).map_err(|_| AssetError::invalid())?, end };
        self.reply.set(reply).map_err(|_| AssetError::invalid())
    }
    pub(super) fn view(&self, state: &DocumentState, link: &Arc<requests::NativeLink>) -> Option<agent::Prepared> {
        let (slot, preview, end) = self.loaded(state, link).ok()?;
        let reply = self.reply.get()?;
        if reply.operation != slot.owner.id || reply.context != slot.context.as_ref()?.revision
            || reply.revision > state.revision || reply.token.as_str() != preview.token.0 || reply.end != end {
            return None;
        }
        let value = agent::Prepared { credential_kind: if self.kind == Kind::AndroidKeystore { None } else { credential::public_kind(self.kind) }, asset_operation_id: reply.operation, status_revision: reply.revision,
            context_revision: reply.context, record_id: Id::parse(&self.reference.record.token()).ok()?,
            expected_revision: self.reference.revision.counter, preview_token: reply.token.clone(),
            remaining_ms: u64::try_from(end.saturating_duration_since(Instant::now()).as_millis()).ok()? };
        value.valid().then_some(value)
    }
    #[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
    pub(super) fn run(&self, document: &DocumentBinding, link: Arc<requests::NativeLink>) -> Result<u32, AssetError> {
        document.reconcile();
        let mut state = document.lock();
        document.expire(&mut state, Instant::now());
        let context = state.context.clone().ok_or_else(AssetError::invalid)?;
        let (id, go) = document.prepare_stored_vault_agent(&mut state, self.reference.key(), context, Some(link))?;
        drop(state);
        let _ = go.send(()); // Original install sender, after the real Doc cut.
        Ok(id)
    }
}

pub(super) fn normal_returns(owner: &Arc<OriginalWork>) -> bool {
    owner.coordinator.try_lock().is_ok_and(|b| b.receipt == JoinReceipt::Returned && b.handle.is_none())
        && owner.child.try_lock().is_ok_and(|b| matches!(b.receipt, JoinReceipt::Returned | JoinReceipt::New) && b.handle.is_none())
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[test]
    fn selected_row_is_exact_full_reference_and_never_an_inert_return_receipt() {
        // Original data types only. Zero-mode lifecycle witness is deliberately
        // not a usable Store read, authenticated Load or native capability.
        let id = |v| format::Id::from_bytes([v; 16]).unwrap();
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let revision = format::Revision::new(id(4), 1).unwrap();
        let mut state = crate::asset_session::tests::empty_state();
        let mut session = Session::new(Arc::new(Mutex::new(store::StoreBook::new())), 7);
        session.identity = Some(identity);
        session.rows.push(Descriptor {
            authenticated: crypto::AuthenticatedDescriptor { record: id(3), revision,
                descriptor: format::Descriptor::new(Kind::AndroidKeystore, None, vec![true; 3], true).unwrap() },
            original: store::ReadWitness::lifecycle_data(id(3), revision), mutation_pending: false,
        });
        state.vault = Some(session);
        let record = Id::parse(&id(3).token()).unwrap();
        let selected = Selection::capture(&state, &record, 1)
            .unwrap_or_else(|_| panic!("the exact synthetic saved row must be selected"));
        let actual = state.vault.as_ref().unwrap().rows[0].reference(identity);
        assert!(same_reference(selected.reference, actual));
        assert!(selected.current(&state).is_err()); // No context/key/native ownership was created.
        assert!(selected.reply.get().is_none());
        let mut different = actual;
        different.revision = format::Revision::new(id(5), 1).unwrap();
        assert!(!same_reference(selected.reference, different));
        different = actual;
        different.original = store::ReadWitness::lifecycle_data(id(3), different.revision);
        assert!(same_reference(selected.reference, different));
        different.original = store::ReadWitness::lifecycle_data(id(3), format::Revision::new(id(6), 1).unwrap());
        assert!(!same_reference(selected.reference, different));
        state.vault.as_mut().unwrap().rows[0].mutation_pending = true;
        assert!(Selection::capture(&state, &record, 1).is_err());
        state.vault.as_mut().unwrap().rows[0].mutation_pending = false;
        assert!(Selection::capture(&state, &record, 2).is_err());
        state.vault.as_mut().unwrap().rows[0].authenticated.descriptor =
            format::Descriptor::new(Kind::AscP8, None, vec![true; 2], true).unwrap();
        assert!(Selection::capture(&state, &record, 1).is_err());
        let generic=Selection::capture_credential(&state,&record,1,Kind::AscP8).unwrap_or_else(|_|panic!("exact inert P8 row"));
        assert_eq!(generic.delegate_kind(),agent::Kind::CredentialAssessExisting);
        assert!(same_reference(generic.reference,actual));
        assert!(generic.current(&state).is_err()); // Row DATA still cannot mint a loaded key/receipt.
        assert!(generic.reply.get().is_none());
        for kind in [Kind::AppleP12,Kind::AndroidKeystore,Kind::GoogleWif,Kind::AppleDistributionKey] {
            assert!(Selection::capture_credential(&state,&record,1,kind).is_err());
        }
    }

    #[test]
    fn original_weak_body_and_one_reply_token_are_reserved_before_attachment() {
        let id = |v| format::Id::from_bytes([v; 16]).unwrap();
        let revision = format::Revision::new(id(4), 1).unwrap();
        let selected = Selection { kind: Kind::AndroidKeystore, reference: StoredRef { identity: format::Identity::new(id(1), id(2)).unwrap(),
            record: id(3), revision, original: store::ReadWitness::lifecycle_data(id(3), revision) },
            original: OnceLock::new(), reply: OnceLock::new() };
        let before = selected.extra_bytes();
        let original = OriginalWork::new(7, false, Weak::new());
        let endpoint = original.endpoint();
        selected.original.set(Arc::downgrade(&original)).ok().unwrap();
        assert_eq!(selected.extra_bytes(), before);
        assert_eq!(before, 2 * std::mem::size_of::<usize>() + std::mem::size_of::<OriginalWork>() + 32);
        assert!(!normal_returns(&original));
        assert_eq!(original.endpoint(), endpoint);
        assert!(!original.stopped());
        assert!(selected.reply.get().is_none());
        drop(original);
        assert!(selected.original.get().unwrap().upgrade().is_none());
        assert_eq!(selected.extra_bytes(), before); // Weak tombstone still owns the allocation body.
    }
}
