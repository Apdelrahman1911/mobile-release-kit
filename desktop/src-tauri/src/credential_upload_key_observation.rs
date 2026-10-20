//! Nonshipping installed adapter into the actual upload-key/vault originals.
//! No private value, user path, tool pathname or result-shaped grant is accepted.
//! All observation storage is fixed, nonsecret DATA; it cannot settle anything.
use super::*;
#[path = "credential_upload_key_cancel_observation.rs"]
mod cancelled;
pub(super) use cancelled::cancelled_disposed;
use crate::shell::installed_observation::vault::{
    upload_key::{Action, Case, Selection},
    Control,
};

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProducerSample {
    pub(crate) ready: bool,
    pub(crate) go_claimed: bool,
    pub(crate) go_sent: bool,
    pub(crate) reader_joined: bool,
    pub(crate) result_complete: bool,
    pub(crate) candidate: bool,
    pub(crate) inspector_started: bool,
    pub(crate) inspector_joined: bool,
    pub(crate) acquisition_started: bool,
    pub(crate) acquisition_joined: bool,
    pub(crate) driver_joined: bool,
    pub(crate) manager_joined: bool,
    pub(crate) watchdog_joined: bool,
    pub(crate) tail_closed: bool,
    pub(crate) original_final: bool,
    pub(crate) cleanup_unknown: bool,
    pub(crate) private_disposed: bool,
}
impl ProducerSample {
    fn generated(self) -> bool {
        self.ready
            && self.go_claimed
            && self.go_sent
            && self.reader_joined
            && self.result_complete
            && self.candidate
            && self.inspector_started
            && self.inspector_joined
            && self.acquisition_started
            && self.acquisition_joined
            && self.driver_joined
            && self.manager_joined
            && self.watchdog_joined
            && self.tail_closed
            && self.original_final
            && !self.cleanup_unknown
            && !self.private_disposed
    }
}

/// The original observer retains a weak identity and a full nonsecret reference,
/// not the VaultKey, JKS, passwords, native run or a second disposal obligation.
#[derive(Default)]
pub(crate) struct Trace {
    original: Weak<OriginalWork>,
    context: u32,
    reference: Option<StoredRef>,
    producer: Option<ProducerSample>,
    reserved: bool,
    authenticated: bool,
    recorded: bool,
    disposed: bool,
    native_use_retired: bool,
    checkpoint: Option<Cut>,
    cancelled_disposal: bool,
    stopped_preference_revision: Option<u64>,
    recovery_request: Option<controls::RecoveryRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cut {
    BeforeGo,
    AfterNew,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sample {
    operation_id: u32,
    reserved: bool,
    authenticated_new: bool,
    recorded: bool,
    published: bool,
    private_disposed: bool,
    native_use_retired: bool,
    native_use_retained: bool,
    private_retained: bool,
    stopped: bool,
    clock_failed: bool,
    clock_retired: bool,
    coordinator_joined: bool,
    child_joined: bool,
    sources_closed: bool,
    parent_ended: bool,
    document_unknown: bool,
    unassigned: bool,
    checkpoint: &'static str,
    cancelled_disposal: bool,
    stopped_preference_revision: Option<u64>,
    // `producer` is the captured actual authenticated-NEW boundary when one
    // exists; otherwise it is the current pre-GO observation. A later STOP
    // cannot rewrite that earlier receipt, nor hide the current retained axes.
    producer: Option<ProducerSample>,
    retained_producer: Option<ProducerSample>,
}
impl Sample {
    pub(crate) fn positive(self) -> bool {
        self.operation_id == 5
            && self.reserved
            && self.authenticated_new
            && self.recorded
            && self.published
            && self.private_disposed
            && self.native_use_retired
            && !self.native_use_retained
            && !self.private_retained
            && !self.stopped
            && !self.clock_failed
            && self.clock_retired
            && self.coordinator_joined
            && self.child_joined
            && self.sources_closed
            && self.parent_ended
            && !self.document_unknown
            && self.unassigned
            && self.checkpoint == "none"
            && !self.cancelled_disposal
            && self.stopped_preference_revision.is_none()
            && self.producer.is_some_and(ProducerSample::generated)
            && self.retained_producer.is_none()
    }
    /// A negative observation is NEVER a disposal/exit/finality permission.
    /// Even an exact checkpoint cannot turn a lost join into a successful test.
    pub(crate) fn stopped_observed(self, case: Case) -> bool {
        let cut = match case {
            Case::RoundTrip => return false,
            Case::StopBeforeGo => "before-go",
            Case::StopAfterNew => "after-new-before-journal",
        };
        self.operation_id == 5
            && self.reserved
            && self.stopped
            && self.clock_failed
            && !self.clock_retired
            && self.native_use_retained
            && self.private_retained
            && !self.private_disposed
            && !self.native_use_retired
            && !self.recorded
            && !self.published
            && self.unassigned
            && self.checkpoint == cut
            && match case {
                Case::StopBeforeGo => {
                    !self.authenticated_new
                        && self
                            .producer
                            .is_some_and(|p| p.ready && !p.go_claimed && !p.go_sent && !p.candidate)
                }
                Case::StopAfterNew => {
                    self.authenticated_new && self.producer.is_some_and(ProducerSample::generated)
                }
                Case::RoundTrip => false,
            }
    }
}

fn fixture(held: &Holding) -> Option<&Arc<Control>> {
    held.setup.installed_control()
}
fn same(trace: &Trace, owner: &Arc<OriginalWork>, context: u32) -> bool {
    trace.context == context
        && trace
            .original
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, owner))
}
pub(super) fn bind(held: &Holding) -> Result<(), Reason> {
    let Some(control) = fixture(held) else {
        return Ok(());
    };
    let owner = held.owner.upgrade().ok_or(Reason::DocumentLost)?;
    let mut trace = control
        .upload
        .trace
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if trace.original.upgrade().is_some()
        || trace.context != 0
        || owner.id != 5
        || held.reservation.get().is_some()
        || held.run.get().is_some()
    {
        return Err(Reason::ContextStale);
    }
    trace.original = Arc::downgrade(&owner);
    trace.context = held.context.revision;
    Ok(())
}
pub(super) fn stored(held: &Holding) -> Result<(), Reason> {
    let Some(control) = fixture(held) else {
        return Ok(());
    };
    let owner = held.owner.upgrade().ok_or(Reason::DocumentLost)?;
    let progress = held
        .progress
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    let reference = progress.saved.ok_or(Reason::VaultCorrupt)?;
    let producer = held
        .run
        .get()
        .and_then(|r| r.installed_upload_sample())
        .ok_or(Reason::CleanupUnknown)?;
    if progress.phase != ProgressPhase::Stored
        || !progress.saved_effect_known()
        || !producer.generated()
        || !owner
            .child
            .try_lock()
            .is_ok_and(|c| c.handle.is_none() && c.receipt == JoinReceipt::Returned)
        || held.reservation.get().is_none()
    {
        return Err(Reason::CleanupUnknown);
    }
    let mut trace = control
        .upload
        .trace
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !same(&trace, &owner, held.context.revision) || trace.reference.is_some() {
        return Err(Reason::ContextStale);
    }
    trace.reference = Some(reference);
    trace.producer = Some(producer);
    trace.reserved = true;
    trace.authenticated = true;
    Ok(())
}
pub(super) fn disposed(held: &Holding) -> Result<(), Reason> {
    let Some(control) = fixture(held) else {
        return Ok(());
    };
    let owner = held.owner.upgrade().ok_or(Reason::DocumentLost)?;
    let p = held
        .progress
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !p.published()
        || !held.native_use_retired.load(Ordering::SeqCst)
        || !held.run.get().is_some_and(|run| {
            run.private_disposed() && run.native_settled() && !run.cleanup_unknown()
        })
    {
        return Err(Reason::CleanupUnknown);
    }
    let mut trace = control
        .upload
        .trace
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    if !same(&trace, &owner, held.context.revision)
        || !trace
            .reference
            .zip(p.saved)
            .is_some_and(|(a, b)| same_reference(a, b))
        || !trace.authenticated
    {
        return Err(Reason::ContextStale);
    }
    trace.recorded = true;
    trace.disposed = true;
    trace.native_use_retired = true;
    // The observation itself is TRY-only. Still recheck the SAME endpoint
    // before the parent can drop Holding and retire it; no fixture IO, sample
    // or observer budget may erase an expired generation deadline.
    if Instant::now() >= held.clock.work_end() {
        parent_stop(&owner, Reason::Deadline, held.clock.work_end());
        return Err(Reason::Deadline);
    }
    if owner.interrupted() || held.clock.failed.load(Ordering::SeqCst) {
        return Err(Reason::ContextStale);
    }
    Ok(())
}

/// Invoked in the SAME original writer/coordinator at its actual boundary.
/// No blocking worker, reentry into native Registry or synthesized join.
pub(super) fn checkpoint(held: &Holding, cut: Cut) -> Result<(), Reason> {
    let Some(control) = fixture(held) else {
        return Ok(());
    };
    if !control.upload.case(control.case).is_some_and(|case| {
        matches!(
            (case, cut),
            (Case::StopBeforeGo, Cut::BeforeGo) | (Case::StopAfterNew, Cut::AfterNew)
        )
    }) {
        return Ok(());
    }
    let owner = held.owner.upgrade().ok_or(Reason::DocumentLost)?;
    let document = DocumentBinding {
        inner: held.document.upgrade().ok_or(Reason::DocumentLost)?,
    };
    let mut state = document.lock();
    if !control.permits(&document.inner.session_identity)
        || state.next_operation != 5
        || !state.slot.as_ref().is_some_and(|s| {
            Arc::ptr_eq(&s.owner, &owner) && s.operation == Operation::GenerateUploadKey
        })
        || held.reservation.get().is_none()
        || owner.interrupted()
    {
        return Err(Reason::ContextStale);
    }
    {
        let mut trace = control
            .upload
            .trace
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !same(&trace, &owner, held.context.revision)
            || trace.checkpoint.is_some()
            || cut == Cut::AfterNew && !trace.authenticated
        {
            return Err(Reason::ContextStale);
        }
        trace.reserved = true;
        trace.checkpoint = Some(cut);
    }
    let at = Instant::now();
    state
        .slot
        .as_mut()
        .ok_or(Reason::ContextStale)?
        .stop(Reason::UserCancelled, at);
    parent_stop(&owner, Reason::UserCancelled, at);
    document.bump(&mut state);
    Err(Reason::UserCancelled)
}

impl DocumentBinding {
    /// Action selection and root come only from the registered original
    /// observation. Reading this adapter never creates state or authority.
    fn installed_upload_control(&self) -> Result<Arc<Control>, AssetError> {
        let book = self
            .inner
            .installed_macos_session
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        let control = book
            .as_ref()
            .and_then(|book| book.vault.as_ref())
            .ok_or_else(AssetError::invalid)?;
        if control.upload.case(control.case).is_none()
            || !control.permits(&self.inner.session_identity)
        {
            return Err(AssetError::new(Reason::Unqualified));
        }
        Ok(control.clone())
    }
    pub(crate) fn installed_upload_select(&self, action: Action) -> Result<Selection, AssetError> {
        let control = self.installed_upload_control()?;
        let state = self.lock();
        control
            .upload
            .select(
                control.clone(),
                &self.inner.session_identity,
                action,
                state.next_operation,
            )
            .ok_or_else(AssetError::invalid)
    }
    pub(crate) fn installed_upload_context(
        &self,
        base: &Value,
        project_id: &str,
        again: bool,
    ) -> Result<(), AssetError> {
        let control = self.installed_upload_control()?;
        let (id, selection) = {
            let state = self.lock();
            let roster = self
                .inner
                .bridge
                .native_roster()
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            if roster.generation != 2
                || roster.roots.len() != 1
                || roster.roots[0].path != control.project()
            {
                return Err(AssetError::new(Reason::ContextStale));
            }
            let action = if again {
                Action::Recontext
            } else {
                Action::Context
            };
            let selection = control
                .upload
                .select(
                    control.clone(),
                    &self.inner.session_identity,
                    action,
                    state.next_operation,
                )
                .ok_or_else(AssetError::invalid)?;
            let (generation, root) = self
                .inner
                .bridge
                .native_project(project_id)
                .map_err(|_| AssetError::invalid())?;
            if generation != roster.generation || root.path != control.project() {
                return Err(AssetError::invalid());
            }
            (project_id.to_owned(), selection)
        };
        self.installed_upload_consume(selection, None)?;
        self.context(commands::Context {
            project_id: &id,
            draft: base,
            platform: Platform::Android,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
            execution_mode: commands::ExecutionMode::Github,
        })?;
        Ok(())
    }
    pub(crate) fn installed_upload_consume(
        &self,
        selection: Selection,
        path: Option<&std::path::Path>,
    ) -> Result<Arc<Control>, AssetError> {
        let state = self.lock();
        selection
            .consume(&self.inner.session_identity, state.next_operation, path)
            .ok_or_else(AssetError::invalid)
    }
    pub(crate) async fn installed_upload_saved(&self) -> Result<(), AssetError> {
        self.installed_upload_saved_action(Action::Saved).await
    }
    async fn installed_upload_saved_action(&self, action: Action) -> Result<(), AssetError> {
        if !matches!(action, Action::Saved | Action::RecoverySaved) { return Err(AssetError::invalid()); }
        let selection = self.installed_upload_select(action)?;
        self.installed_upload_consume(selection, None)?;
        let project = self
            .lock()
            .context
            .as_ref()
            .ok_or_else(AssetError::invalid)?
            .project_id
            .clone();
        self.inner
            .bridge
            .observe_release_version(
                self,
                crate::release_version_protocol::Request {
                    project_id: project,
                },
            )
            .await
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        Ok(())
    }
    pub(crate) async fn installed_upload_prepare(&self) -> Result<(), AssetError> {
        let control = self.installed_upload_control()?;
        let request = controls::ContextRequest {
            context_revision: self
                .lock()
                .context
                .as_ref()
                .ok_or_else(AssetError::invalid)?
                .revision,
        };
        let selection = self.installed_upload_select(Action::Prepare)?;
        self.prepare_upload_key_setup_selected(
            request,
            control.root(),
            controls::Qualification::Installed(selection),
        )
        .await?;
        Ok(())
    }
    pub(crate) fn installed_upload_create(&self, repeated: bool) -> Result<bool, AssetError> {
        let state = self.lock();
        let context = state
            .context
            .as_ref()
            .ok_or_else(AssetError::invalid)?
            .revision;
        let original = state.next_operation;
        let request = controls::create_request(&serde_json::json!({"contextRevision":context,
            "expectedStatusRevision":state.revision,"declaration":"new-application-no-existing-upload-key"}))?;
        drop(state);
        let selection = self.installed_upload_select(if repeated {
            Action::RefuseRepeat
        } else {
            Action::Create
        })?;
        let result =
            self.create_upload_key_selected(request, controls::Qualification::Installed(selection));
        if repeated {
            let state = self.lock();
            Ok(result.is_err()
                && original == 5
                && state.next_operation == original
                && state.slot.as_ref().is_some_and(|slot| {
                    slot.operation == Operation::GenerateUploadKey && slot.owner.id == original
                }))
        } else {
            result.map(|_| true)
        }
    }
    pub(crate) fn installed_upload_vault(&self, action: Action) -> Result<(), AssetError> {
        let selection = self.installed_upload_select(action)?;
        let control = self.installed_upload_control()?;
        let path = (action == Action::Reopen).then(|| control.root());
        self.installed_upload_consume(selection, path)?;
        match action {
            Action::Lock | Action::Relock | Action::RecoveredRelock | Action::Missing => {
                self.lock_session()?;
            }
            Action::Reopen => {
                self.open_encrypted(control.root())?;
            }
            Action::Unlock => {
                self.unlock_vault()?;
            }
            Action::Read => {
                let expected = control
                    .upload
                    .trace
                    .try_lock()
                    .map_err(|_| AssetError::new(Reason::Busy))?
                    .reference
                    .ok_or_else(AssetError::invalid)?;
                let mut state = self.lock();
                let context = state.context.clone().ok_or_else(AssetError::invalid)?;
                let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
                if !session.identity.is_some_and(|id| id == expected.identity)
                    || !session
                        .row(&expected.key())
                        .is_some_and(|r| same_reference(r.reference(expected.identity), expected))
                {
                    return Err(AssetError::new(Reason::SourceChanged));
                }
                let (_, start) = self.prepare_stored_vault(&mut state, expected.key(), context)?;
                drop(state);
                let _ = start.send(());
            }
            _ => return Err(AssetError::invalid()),
        }
        Ok(())
    }
    pub(crate) fn installed_upload_readback(&self) -> Option<bool> {
        let control = self.installed_upload_control().ok()?;
        let trace = control.upload.trace.try_lock().ok()?;
        let expected = trace.reference?;
        let state = self.inner.state.try_lock().ok()?;
        let slot = state.slot.as_ref()?;
        if slot.owner.id != 8 || slot.operation != Operation::Prepare {
            return Some(false);
        }
        if state.unknown || slot.owner.stopped() || slot.reason != Reason::None {
            return Some(false);
        }
        if slot.phase != Phase::Preview || slot.settlement != Settlement::Known {
            return None;
        }
        Some(
            slot.vault
                .reference
                .is_some_and(|r| same_reference(r, expected))
                && slot
                    .vault
                    .loaded
                    .as_ref()
                    .is_some_and(|p| p.kind == Kind::AndroidKeystore && p.material.is_some())
                && slot.owner.ended.load(Ordering::SeqCst)
                && slot.owner.resources_settled()
                && state.assignments.is_empty()
                && state
                    .vault
                    .as_ref()
                    .is_some_and(|v| v.bound.iter().all(Option::is_none)),
        )
    }
    pub(crate) fn installed_upload_sample(&self) -> Option<Sample> {
        let control = self.installed_upload_control().ok()?;
        let state = self.inner.state.try_lock().ok()?;
        let trace = control.upload.trace.try_lock().ok()?;
        let owner = trace.original.upgrade()?;
        let work = owner.vault.try_lock().ok()?;
        let retirement = owner.retirement.try_lock().ok()?;
        let held = work
            .upload_key
            .inner
            .as_ref()
            .or(retirement.vault.upload_key.inner.as_ref());
        let retained_producer = held.and_then(|held| held.run.get()?.installed_upload_sample());
        let producer = trace.producer.or(retained_producer);
        let clock = owner.upload_key_clock.get()?;
        let p = held.map(|held| held.progress.try_lock()).transpose().ok()?;
        Some(Sample {
            operation_id: owner.id,
            reserved: trace.reserved || held.is_some_and(|h| h.reservation.get().is_some()),
            authenticated_new: trace.authenticated,
            recorded: trace.recorded || p.as_ref().is_some_and(|p| p.journal_revision.is_some()),
            published: trace.recorded || p.as_ref().is_some_and(|p| p.published()),
            private_disposed: trace.disposed && held.is_none(),
            native_use_retired: trace.native_use_retired,
            native_use_retained: held.is_some_and(|h| {
                h.native_use.get().is_some() && !h.native_use_retired.load(Ordering::SeqCst)
            }),
            private_retained: held.is_some(),
            stopped: owner.stopped(),
            clock_failed: clock.failed.load(Ordering::SeqCst),
            clock_retired: clock.completed.load(Ordering::SeqCst),
            coordinator_joined: owner
                .coordinator
                .try_lock()
                .ok()
                .is_some_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::Returned),
            child_joined: owner
                .child
                .try_lock()
                .ok()
                .is_some_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::Returned),
            sources_closed: owner
                .source
                .try_lock()
                .ok()
                .is_some_and(|b| b.not_started() || b.settled()),
            parent_ended: owner.ended.load(Ordering::SeqCst),
            document_unknown: state.unknown,
            unassigned: state.assignments.is_empty()
                && state
                    .vault
                    .as_ref()
                    .is_some_and(|v| v.bound.iter().all(Option::is_none)),
            checkpoint: match trace.checkpoint {
                None => "none",
                Some(Cut::BeforeGo) => "before-go",
                Some(Cut::AfterNew) => "after-new-before-journal",
            },
            cancelled_disposal: trace.cancelled_disposal,
            stopped_preference_revision: trace.stopped_preference_revision,
            producer,
            retained_producer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved_data() -> Sample {
        Sample {
            operation_id: 5,
            reserved: true,
            authenticated_new: true,
            recorded: true,
            published: true,
            private_disposed: true,
            native_use_retired: true,
            native_use_retained: false,
            private_retained: false,
            stopped: false,
            clock_failed: false,
            clock_retired: true,
            coordinator_joined: true,
            child_joined: true,
            sources_closed: true,
            parent_ended: true,
            document_unknown: false,
            unassigned: true,
            checkpoint: "none",
            cancelled_disposal: false,
            stopped_preference_revision: None,
            producer: Some(ProducerSample {
                ready: true,
                go_claimed: true,
                go_sent: true,
                reader_joined: true,
                result_complete: true,
                candidate: true,
                inspector_started: true,
                inspector_joined: true,
                acquisition_started: true,
                acquisition_joined: true,
                driver_joined: true,
                manager_joined: true,
                watchdog_joined: true,
                tail_closed: true,
                original_final: true,
                cleanup_unknown: false,
                private_disposed: false,
            }),
            retained_producer: None,
        }
    }

    #[test]
    fn completed_data_needs_started_producers_and_actual_parent_disposal_axes() {
        // Literal DATA cannot construct a Document, candidate or join receipt.
        let s = saved_data();
        assert!(s.positive());
        let p = s.producer.unwrap();
        for producer in [
            ProducerSample {
                inspector_started: false,
                ..p
            },
            ProducerSample {
                acquisition_started: false,
                ..p
            },
            ProducerSample {
                reader_joined: false,
                ..p
            },
            ProducerSample {
                tail_closed: false,
                ..p
            },
            ProducerSample {
                original_final: false,
                ..p
            },
            ProducerSample {
                cleanup_unknown: true,
                ..p
            },
        ] {
            assert!(!Sample {
                producer: Some(producer),
                ..s
            }
            .positive());
        }
        for s in [
            Sample {
                coordinator_joined: false,
                ..s
            },
            Sample {
                child_joined: false,
                ..s
            },
            Sample {
                sources_closed: false,
                ..s
            },
            Sample {
                private_retained: true,
                ..s
            },
            Sample {
                clock_retired: false,
                ..s
            },
            Sample {
                clock_failed: true,
                ..s
            },
            Sample {
                retained_producer: Some(p),
                ..s
            },
        ] {
            assert!(!s.positive());
        }
    }

    #[test]
    fn after_new_snapshot_does_not_relabel_current_native_unknown_as_joined() {
        let s = saved_data();
        let current = ProducerSample {
            cleanup_unknown: true,
            ..ProducerSample::default()
        };
        let s = Sample {
            recorded: false,
            published: false,
            private_disposed: false,
            native_use_retired: false,
            native_use_retained: true,
            private_retained: true,
            stopped: true,
            clock_failed: true,
            clock_retired: false,
            coordinator_joined: false,
            child_joined: false,
            sources_closed: false,
            parent_ended: false,
            document_unknown: true,
            checkpoint: "after-new-before-journal",
            retained_producer: Some(current),
            ..s
        };
        assert!(s.stopped_observed(Case::StopAfterNew));
        assert!(s.retained_producer.unwrap().cleanup_unknown);
        assert!(!s.retained_producer.unwrap().original_final);
        assert!(!s.positive());
        assert!(!Sample {
            authenticated_new: false,
            ..s
        }
        .stopped_observed(Case::StopAfterNew));
    }

    #[test]
    fn an_expected_stop_is_not_positive_finality() {
        // Comparison DATA only; no Document, producer, selection or native key.
        let mut s = Sample {
            operation_id: 5,
            reserved: true,
            authenticated_new: false,
            recorded: false,
            published: false,
            private_disposed: false,
            native_use_retired: false,
            native_use_retained: true,
            private_retained: true,
            stopped: true,
            clock_failed: true,
            clock_retired: false,
            coordinator_joined: false,
            child_joined: false,
            sources_closed: false,
            parent_ended: false,
            document_unknown: true,
            unassigned: true,
            checkpoint: "before-go",
            cancelled_disposal: false,
            stopped_preference_revision: None,
            producer: Some(ProducerSample {
                ready: true,
                ..ProducerSample::default()
            }),
            retained_producer: None,
        };
        assert!(s.stopped_observed(Case::StopBeforeGo));
        assert!(!s.positive());
        s.private_retained = false;
        assert!(!s.stopped_observed(Case::StopBeforeGo));
        s.private_retained = true;
        s.producer.as_mut().unwrap().go_claimed = true;
        assert!(!s.stopped_observed(Case::StopBeforeGo));
    }
}
