//! The cold process has no producer Trace or inherited private authority.
//! It loads the sole freshly authenticated row, then consumes the REAL Bind
//! preview. Cross-process continuity is checked by the original fixture FD
//! owner; no path, reference, hash or success receipt is imported here.
use super::*;
use crate::shell::installed_observation::vault::upload_key::restart::Action as ColdAction;

#[derive(Default)]
pub(crate) struct ColdState {
    reference: Option<StoredRef>,
    load: Weak<OriginalWork>,
    bound: Weak<OriginalWork>,
}

impl DocumentBinding {
    fn installed_cold_control(&self) -> Result<Arc<Control>, AssetError> {
        let control = self.installed_upload_control()?;
        if control.upload.case(control.case) != Some(Case::ColdReopen) {
            return Err(AssetError::invalid());
        }
        Ok(control)
    }

    fn installed_cold_claim(&self, action: ColdAction) -> Result<Arc<Control>, AssetError> {
        let control = self.installed_cold_control()?;
        let state = self.lock();
        let selection = control
            .upload
            .cold
            .select(
                control.clone(),
                &self.inner.session_identity,
                action,
                state.next_operation,
            )
            .ok_or_else(AssetError::invalid)?;
        selection
            .consume(&self.inner.session_identity, state.next_operation)
            .ok_or_else(AssetError::invalid)
    }

    pub(crate) fn installed_cold_unlock(&self) -> Result<(), AssetError> {
        self.installed_cold_claim(ColdAction::Unlock)?;
        // Ordinary lookup on the actual newly opened Store/Keychain owner.
        self.unlock_vault()?;
        Ok(())
    }

    pub(crate) fn installed_cold_context(
        &self,
        draft: &Value,
        project: &str,
    ) -> Result<(), AssetError> {
        let control = self.installed_cold_control()?;
        let roster = self
            .inner
            .bridge
            .native_roster()
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(project)
            .map_err(|_| AssetError::invalid())?;
        if roster.generation != 2
            || generation != roster.generation
            || roster.roots.len() != 1
            || roster.roots[0].path != control.project()
            || root.path != control.project()
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        self.installed_cold_claim(ColdAction::Context)?;
        self.context(commands::Context {
            project_id: project,
            draft,
            platform: Platform::Android,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
            execution_mode: commands::ExecutionMode::Github,
        })?;
        Ok(())
    }

    pub(crate) fn installed_cold_load(&self) -> Result<(), AssetError> {
        let control = self.installed_cold_claim(ColdAction::Load)?;
        let mut state = self.lock();
        let context = state.context.clone().ok_or_else(AssetError::invalid)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        if state.next_operation != 3
            || state.unknown
            || !state.assignments.is_empty()
            || session.revoked
            || session.read_only
            || session.state != State::Unlocked
            || session.key.is_none()
            || session.rows.len() != 1
            || session.inventory.len() != 1
            || session.bound.iter().any(Option::is_some)
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let row = &session.rows[0];
        if row.mutation_pending
            || row.authenticated.descriptor.kind != Kind::AndroidKeystore
            || session.inventory[0] != row.authenticated.record
            || row.authenticated.revision.counter != 1
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let reference = row.reference(session.identity.ok_or_else(AssetError::invalid)?);
        let mut cold = control
            .upload
            .cold
            .native
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        if cold.reference.is_some()
            || cold.load.upgrade().is_some()
            || cold.bound.upgrade().is_some()
        {
            return Err(AssetError::invalid());
        }
        // This is the fresh process's actual singleton descriptor. It grants
        // no authentication/Bind: the original Load and assessment must return.
        cold.reference = Some(reference);
        let (id, start) = self.prepare_stored_vault(&mut state, reference.key(), context)?;
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        if id != 4 || slot.owner.id != id {
            return Err(AssetError::invalid());
        }
        cold.load = Arc::downgrade(&slot.owner);
        drop(cold);
        drop(state);
        let _ = start.send(());
        Ok(())
    }

    pub(crate) fn installed_cold_loaded(&self) -> Option<bool> {
        let control = self.installed_cold_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let cold = control.upload.cold.native.try_lock().ok()?;
        let reference = cold.reference?;
        let original = cold.load.upgrade()?;
        let slot = state.slot.as_ref()?;
        if state.next_operation != 4
            || slot.owner.id != 4
            || !Arc::ptr_eq(&slot.owner, &original)
            || slot.operation != Operation::Prepare
            || state.unknown
            || slot.owner.stopped()
            || slot.reason != Reason::None
            || slot.error.is_some()
            || slot.settlement == Settlement::Unknown
        {
            return Some(false);
        }
        if slot.phase != Phase::Preview
            || slot.settlement != Settlement::Known
            || !slot.owner.ended.load(Ordering::SeqCst)
            || !slot.owner.resources_settled()
        {
            return None;
        }
        Some(
            slot.vault
                .reference
                .is_some_and(|held| same_reference(held, reference))
                && slot.vault.loaded.as_ref().is_some_and(|payload| {
                    payload.kind == Kind::AndroidKeystore
                        && payload.material.as_ref().is_some_and(|material| {
                            matches!(&material.origin,
                    MaterialOrigin::Stored(stored) if same_reference(stored.reference, reference))
                        })
                })
                && slot
                    .assessment
                    .as_ref()
                    .is_some_and(SafeAssessment::permits)
                && state
                    .context
                    .as_ref()
                    .is_some_and(|context| self.context_matches(&state, context).unwrap_or(false))
                && state.assignments.is_empty()
                && state
                    .vault
                    .as_ref()
                    .is_some_and(|session| session.bound.iter().all(Option::is_none)),
        )
    }

    pub(crate) fn installed_cold_bind(&self) -> Result<(), AssetError> {
        if self.installed_cold_loaded() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_cold_control()?;
        let token = {
            let state = self.lock();
            let cold = control
                .upload
                .cold
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            let reference = cold.reference.ok_or_else(AssetError::invalid)?;
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let preview = slot.preview.as_ref().ok_or_else(AssetError::invalid)?;
            if slot.owner.id != 4
                || !cold
                    .load
                    .upgrade()
                    .is_some_and(|old| Arc::ptr_eq(&old, &slot.owner))
                || preview.action != crate::asset_session::Action::Bind
                || !preview
                    .record
                    .as_ref()
                    .is_some_and(|record| reference.matches(record))
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            preview.token.0.clone()
        };
        self.installed_cold_claim(ColdAction::Bind)?;
        self.bind(&token)?;
        let state = self.lock();
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        if state.next_operation != 5 || slot.owner.id != 5 || slot.operation != Operation::Bind {
            return Err(AssetError::invalid());
        }
        let mut cold = control
            .upload
            .cold
            .native
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        if cold.bound.upgrade().is_some() {
            return Err(AssetError::invalid());
        }
        cold.bound = Arc::downgrade(&slot.owner);
        Ok(())
    }

    pub(crate) fn installed_cold_bound(&self) -> Option<bool> {
        let control = self.installed_cold_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let cold = control.upload.cold.native.try_lock().ok()?;
        let reference = cold.reference?;
        let original = cold.bound.upgrade()?;
        let slot = state.slot.as_ref()?;
        if state.next_operation != 5
            || slot.owner.id != 5
            || !Arc::ptr_eq(&slot.owner, &original)
            || slot.operation != Operation::Bind
            || state.unknown
            || slot.owner.stopped()
            || slot.reason != Reason::None
            || slot.error.is_some()
            || slot.settlement == Settlement::Unknown
        {
            return Some(false);
        }
        if slot.phase != Phase::Idle
            || slot.settlement != Settlement::Known
            || !slot.owner.resources_settled()
        {
            return None;
        }
        Some(
            state
                .context
                .as_ref()
                .is_some_and(|context| self.context_matches(&state, context).unwrap_or(false))
                && remembered_bound_reference(&state, slot, Kind::AndroidKeystore)
                    .is_some_and(|held| same_reference(held, reference)),
        )
    }

    pub(crate) fn installed_cold_lock(&self) -> Result<(), AssetError> {
        if self.installed_cold_bound() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        self.installed_cold_claim(ColdAction::Lock)?;
        self.lock_session()?;
        Ok(())
    }
}
