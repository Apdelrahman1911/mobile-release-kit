//! Nonshipping observation of the existing cancellation/recovery owners.
//! No sample grants disposal, replays generation, or changes an operation result.
use super::*;

/// Called only after the SAME cancellation Retirement's `dispose` returned
/// true: native private disposal, required noGO CAS, and NativeUse retirement
/// have all really returned. The caller ignores this comparison-only tap.
pub(in crate::asset_session) fn cancelled_disposed(held: &Holding, stopped_revision: Option<u64>) {
    let Some(control) = fixture(held) else { return };
    let Some(owner) = held.owner.upgrade() else { return };
    let Some(case) = control.upload.case(control.case) else { return };
    let Ok(progress) = held.progress.try_lock() else { return };
    if !owner.stopped()
        || !held.clock.failed.load(Ordering::SeqCst)
        || !held.native_use_retired.load(Ordering::SeqCst)
        || !held.run.get().is_some_and(|run|
            run.cancelled_private_disposed(&owner, &held.preparation))
        || progress.published() || progress.journal_revision.is_some()
    { return; }
    let Ok(mut trace) = control.upload.trace.try_lock() else { return };
    if !same(&trace, &owner, held.context.revision)
        || trace.cancelled_disposal || trace.disposed || trace.recorded
    { return; }
    let exact = match case {
        Case::RoundTrip | Case::ColdProduce | Case::ColdReopen | Case::BackupRoundTrip => false,
        Case::StopBeforeGo => trace.checkpoint == Some(Cut::BeforeGo)
            && stopped_revision.is_some_and(|revision| revision > 0)
            && !trace.authenticated && trace.reference.is_none()
            && progress.saved.is_none() && progress.outcome.is_none(),
        Case::StopAfterNew => trace.checkpoint == Some(Cut::AfterNew)
            && stopped_revision.is_none() && trace.authenticated
            && trace.reference.zip(progress.saved).is_some_and(|(a, b)| same_reference(a, b))
            && progress.outcome == Some(store::StorageOutcome {
                effect: store::Effect::KnownApplied,
                durability: store::Durability::Confirmed,
                cleanup: store::Cleanup::Known,
            }) && progress.certificate.is_some(),
    };
    if !exact { return; }
    trace.cancelled_disposal = true;
    trace.stopped_preference_revision = stopped_revision;
    trace.disposed = true;
    trace.native_use_retired = true;
}

impl Sample {
    /// Observation only, never a native cancellation/disposal witness. The
    /// completed clock/private-empty axes are read AFTER the original tap;
    /// transient STOP, terminal DTOs, or absent workers cannot satisfy this.
    pub(crate) fn cancelled(self, case: Case) -> bool {
        self.operation_id == 5 && self.reserved && self.cancelled_disposal
            && self.private_disposed && self.native_use_retired
            && !self.native_use_retained && !self.private_retained
            && self.stopped && self.clock_failed && self.clock_retired
            && self.coordinator_joined && self.child_joined && self.sources_closed
            && self.parent_ended && !self.document_unknown && self.unassigned
            && !self.recorded && !self.published && self.retained_producer.is_none()
            && match case {
                Case::RoundTrip | Case::ColdProduce | Case::ColdReopen | Case::BackupRoundTrip => false,
                Case::StopBeforeGo => self.checkpoint == "before-go"
                    && !self.authenticated_new && self.producer.is_none()
                    && self.stopped_preference_revision.is_some_and(|revision| revision > 0),
                Case::StopAfterNew => self.checkpoint == "after-new-before-journal"
                    && self.authenticated_new && self.stopped_preference_revision.is_none()
                    && self.producer.is_some_and(ProducerSample::generated),
            }
    }
}

impl DocumentBinding {
    pub(crate) async fn installed_upload_recovery_saved(&self) -> Result<(), AssetError> {
        self.installed_upload_saved_action(Action::RecoverySaved).await
    }
    pub(crate) async fn installed_upload_recovery_prepare(&self) -> Result<(), AssetError> {
        let control = self.installed_upload_control()?;
        let stopped_revision = {
            let trace = control.upload.trace.try_lock().map_err(|_| AssetError::new(Reason::Busy))?;
            if control.upload.case(control.case) != Some(Case::StopBeforeGo)
                || !trace.cancelled_disposal || trace.reference.is_some()
                || trace.recovery_request.is_some()
            { return Err(AssetError::invalid()); }
            trace.stopped_preference_revision.ok_or_else(AssetError::invalid)?
        };
        let request = controls::ContextRequest {
            context_revision: self.lock().context.as_ref().ok_or_else(AssetError::invalid)?.revision,
        };
        let selection = self.installed_upload_select(Action::RecoveryPrepare)?;
        // Same actual Host/current saved input/Store; no reset of the old
        // generation's attempted flag. This follows genuine Lock/Open/Unlock.
        let status = self.prepare_upload_key_setup_selected(request, control.root(),
            controls::Qualification::Installed(selection)).await?;
        let request = controls::recovery::installed_unstarted_request(&status, stopped_revision)?;
        let mut trace = control.upload.trace.try_lock().map_err(|_| AssetError::new(Reason::Busy))?;
        if trace.recovery_request.is_some()
            || trace.stopped_preference_revision != Some(stopped_revision)
        { return Err(AssetError::new(Reason::ContextStale)); }
        trace.recovery_request = Some(request);
        Ok(())
    }
    pub(crate) fn installed_upload_acknowledge_unstarted(&self) -> Result<(), AssetError> {
        let control = self.installed_upload_control()?;
        let selection = self.installed_upload_select(Action::AcknowledgeUnstarted)?;
        let request = control.upload.trace.try_lock().map_err(|_| AssetError::new(Reason::Busy))?
            .recovery_request.take().ok_or_else(AssetError::invalid)?;
        // Exactly one explicit acknowledgement on the real Recovery original.
        // Its CAS preserves the cancelled intent in history. No Create follows.
        self.recover_upload_key_selected(request, controls::Qualification::Installed(selection))?;
        Ok(())
    }
    pub(crate) fn installed_upload_acknowledged(&self) -> Option<bool> {
        self.reconcile();
        let control = self.installed_upload_control().ok()?;
        if control.upload.case(control.case) != Some(Case::StopBeforeGo) { return Some(false); }
        let trace = control.upload.trace.try_lock().ok()?;
        if !trace.cancelled_disposal || trace.recovery_request.is_some() { return Some(false); }
        let revision = trace.stopped_preference_revision?;
        let state = self.inner.state.try_lock().ok()?;
        if state.next_operation != 8 { return Some(false); }
        controls::recovery::installed_acknowledged(self, &state, revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn no_go_data() -> Sample {
        Sample { operation_id: 5, reserved: true, authenticated_new: false,
            recorded: false, published: false, private_disposed: true,
            native_use_retired: true, native_use_retained: false, private_retained: false,
            stopped: true, clock_failed: true, clock_retired: true,
            coordinator_joined: true, child_joined: true, sources_closed: true,
            parent_ended: true, document_unknown: false, unassigned: true,
            checkpoint: "before-go", cancelled_disposal: true, stopped_preference_revision: Some(3),
            producer: None, retained_producer: None }
    }
    #[test]
    fn cancelled_data_requires_disposal_tap_and_current_private_empty_join_axes() {
        // Literal DATA creates no OriginalWork, key, proof, Store or process.
        let data = no_go_data();
        assert!(data.cancelled(Case::StopBeforeGo));
        assert!(!data.positive());
        for bad in [Sample { cancelled_disposal: false, ..data },
            Sample { clock_retired: false, ..data }, Sample { private_retained: true, ..data },
            Sample { native_use_retained: true, ..data }, Sample { private_disposed: false, ..data },
            Sample { native_use_retired: false, ..data }, Sample { coordinator_joined: false, ..data },
            Sample { child_joined: false, ..data }, Sample { sources_closed: false, ..data },
            Sample { parent_ended: false, ..data }, Sample { document_unknown: true, ..data },
            Sample { stopped: false, ..data }, Sample { clock_failed: false, ..data },
            Sample { recorded: true, ..data }, Sample { published: true, ..data },
            Sample { stopped_preference_revision: None, ..data },
            Sample { stopped_preference_revision: Some(0), ..data }]
        { assert!(!bad.cancelled(Case::StopBeforeGo)); }
    }
    #[test]
    fn no_go_data_never_becomes_saved_or_roundtrip_success() {
        let data = no_go_data();
        assert!(!data.cancelled(Case::StopAfterNew));
        assert!(!data.cancelled(Case::RoundTrip));
        assert!(!Sample { authenticated_new: true, ..data }.cancelled(Case::StopBeforeGo));
        assert!(!Sample { producer: Some(ProducerSample::default()), ..data }.cancelled(Case::StopBeforeGo));
    }
}
