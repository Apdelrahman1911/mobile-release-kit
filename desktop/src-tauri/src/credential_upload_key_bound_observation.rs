//! Nonshipping AfterNEW continuation through the real Bind and recovery owner.
//! A saved reference only compares the original row. It never creates a loan,
//! supplies a replacement assessment, or reclassifies cancelled generation.
use super::*;

impl DocumentBinding {
    fn installed_after_new_reference(&self) -> Result<(Arc<Control>, StoredRef), AssetError> {
        let control = self.installed_upload_control()?;
        let expected = {
            let trace = control
                .upload
                .trace
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            if control.upload.case(control.case) != Some(Case::StopAfterNew)
                || !trace.cancelled_disposal
                || !trace.authenticated
                || !trace.disposed
                || !trace.native_use_retired
                || trace.recorded
                || trace.checkpoint != Some(Cut::AfterNew)
                || trace.stopped_preference_revision.is_some()
            {
                return Err(AssetError::invalid());
            }
            trace.reference.ok_or_else(AssetError::invalid)?
        };
        Ok((control, expected))
    }

    pub(crate) fn installed_upload_bind_saved(&self) -> Result<(), AssetError> {
        let (_, expected) = self.installed_after_new_reference()?;
        self.reconcile();
        let token = {
            let state = self.lock();
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let preview = slot.preview.as_ref().ok_or_else(AssetError::invalid)?;
            if state.next_operation != 8
                || state.unknown
                || slot.owner.id != 8
                || slot.operation != Operation::Prepare
                || slot.phase != Phase::Preview
                || slot.settlement != Settlement::Known
                || slot.reason != Reason::None
                || slot.owner.stopped()
                || !slot.owner.resources_settled()
                || !slot
                    .vault
                    .reference
                    .is_some_and(|actual| same_reference(actual, expected))
                || !slot
                    .assessment
                    .as_ref()
                    .is_some_and(SafeAssessment::permits)
                || preview.action != crate::asset_session::Action::Bind
                || !preview
                    .record
                    .as_ref()
                    .is_some_and(|key| expected.matches(key))
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            // This is the actual original Prepare8 one-use Bind preview token.
            // The unchanged bind() revalidates/consumes it and launches Bind9.
            preview.token.0.clone()
        };
        let selection = self.installed_upload_select(Action::BindSaved)?;
        self.installed_upload_consume(selection, None)?;
        self.bind(&token)?;
        Ok(())
    }

    pub(crate) fn installed_upload_bound_saved(&self) -> Option<bool> {
        let (_, expected) = self.installed_after_new_reference().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let slot = state.slot.as_ref()?;
        if state.next_operation != 9
            || slot.owner.id != 9
            || slot.operation != Operation::Bind
            || state.unknown
            || slot.owner.stopped()
            || slot.reason != Reason::None
            || slot.error.is_some()
            || slot.settlement == Settlement::Unknown
        {
            return Some(false);
        }
        if slot.phase != Phase::Idle || !slot.owner.resources_settled() {
            return None;
        }
        Some(
            state
                .context
                .as_ref()
                .is_some_and(|context| self.context_matches(&state, context).unwrap_or(false))
                && remembered_bound_reference(&state, slot, Kind::AndroidKeystore)
                    .is_some_and(|actual| same_reference(actual, expected)),
        )
    }

    pub(crate) async fn installed_upload_bound_saved_input(&self) -> Result<(), AssetError> {
        if self.installed_upload_bound_saved() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        self.installed_upload_saved_action(Action::BoundSaved).await
    }

    pub(crate) async fn installed_upload_bound_prepare(&self) -> Result<(), AssetError> {
        let (control, expected) = self.installed_after_new_reference()?;
        if self.installed_upload_bound_saved() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        {
            let trace = control
                .upload
                .trace
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            if trace.recovery_request.is_some() || trace.bound_preference_revision.is_some() {
                return Err(AssetError::invalid());
            }
        }
        let request = controls::ContextRequest {
            context_revision: self
                .lock()
                .context
                .as_ref()
                .ok_or_else(AssetError::invalid)?
                .revision,
        };
        let selection = self.installed_upload_select(Action::BoundPrepare)?;
        // A real current saved observation and the same native Host/store are
        // required by the ordinary setup body. No generation is rearmed.
        let status = self
            .prepare_upload_key_setup_selected(
                request,
                control.root(),
                controls::Qualification::Installed(selection),
            )
            .await?;
        let (request, revision) = controls::recovery::installed_bound_request(&status, expected)?;
        if self.installed_upload_bound_saved() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let mut trace = control
            .upload
            .trace
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        if trace.recovery_request.is_some()
            || trace.bound_preference_revision.is_some()
            || !trace
                .reference
                .is_some_and(|actual| same_reference(actual, expected))
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        trace.recovery_request = Some(request);
        trace.bound_preference_revision = Some(revision);
        Ok(())
    }

    pub(crate) fn installed_upload_remember_bound(&self) -> Result<(), AssetError> {
        let (control, _) = self.installed_after_new_reference()?;
        if self.installed_upload_bound_saved() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let selection = self.installed_upload_select(Action::RememberBound)?;
        let request = control
            .upload
            .trace
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?
            .recovery_request
            .take()
            .ok_or_else(AssetError::invalid)?;
        // The same Recovery10 body captures the actual BoundLoan BEFORE its
        // original slot replaces Bind9, then performs Child::Check and one CAS.
        self.recover_upload_key_selected(request, controls::Qualification::Installed(selection))?;
        Ok(())
    }

    pub(crate) fn installed_upload_remembered_bound(&self) -> Option<bool> {
        self.reconcile();
        let (control, expected) = self.installed_after_new_reference().ok()?;
        let previous = {
            let trace = control.upload.trace.try_lock().ok()?;
            if trace.recovery_request.is_some() {
                return Some(false);
            }
            trace.bound_preference_revision?
        };
        let state = self.inner.state.try_lock().ok()?;
        if state.next_operation != 10 {
            return Some(false);
        }
        controls::recovery::installed_remembered(self, &state, expected, previous)
    }
}
