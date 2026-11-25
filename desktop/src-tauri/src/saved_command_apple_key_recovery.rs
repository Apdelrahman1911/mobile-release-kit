//! Exact durable-key comparison on the SAME AppleKeySession. No generator,
//! provider request, historical settlement repair, or transferable key proof.
use super::*;
use crate::apple_provisioning_journal::KeyRecoveryRecord;

#[derive(Default)]
pub(super) struct State {
    compared: OnceLock<wire::KeyRecoveryInput>,
    source_checked: AtomicBool,
    issued: AtomicBool,
}
pub(super) fn backing_bytes() -> Option<usize> {
    // Public CSR/SPKI + bounded record/proof/ACK, plus the existing zeroizing
    // scalar codec's comparison scratch. All old common/journal charges stay.
    (4 * crate::apple_provisioning_journal::ROW_LIMIT)
        .checked_add(crate::asset_commands::APPLE_KEY_CONSTRUCTION_BYTES)?
        .checked_add(std::mem::size_of::<State>())?
        .checked_add(std::mem::size_of::<AppleKeyRecoveryVerified>())
}
fn state(parent: &AppleKeySession) -> Result<&State, BridgeError> {
    parent.recovery.as_ref().ok_or_else(invalid)
}
fn originals(
    owner: &Arc<Session>,
) -> Result<
    (
        Arc<AppleKeySession>,
        Arc<OriginalWork>,
        Arc<AppleDistributionKeyLoan>,
        Arc<wire::RequestBinding>,
    ),
    BridgeError,
> {
    let parent = original(owner)?.clone();
    let asset = parent
        .original
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let loan = parent
        .loan
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(invalid)?;
    let binding = parent.binding.get().ok_or_else(invalid)?.clone();
    if parent.mode != wire::Mode::KeyRecover
        || !parent.same_asset(&asset)
        || !parent.same_binding(&binding)
        || !parent.source_returned.load(Ordering::SeqCst)
        || parent.clock.interrupted()
        || parent.private_drained.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || binding
            .scope
            .key
            .as_ref()
            .and_then(|key| key.source_key.as_ref())
            != Some(&loan.reference())
    {
        return Err(invalid());
    }
    Ok((parent, asset, loan, binding))
}
pub(in crate::saved_command_owner) fn key_ack(
    owner: &Arc<Session>,
    sequence: u32,
    input: wire::KeyRecoveryInput,
) -> Result<Vec<u8>, BridgeError> {
    let (parent, asset, loan, binding) = originals(owner)?;
    owner.apple.input()?.current()?;
    if sequence != 1
        || parent.phase() != Some(SavePhase::Waiting)
        || !loan.matches_public_material(&asset, input.csr.as_bytes(), &input.spki)
        || !loan.matches_recovery_frame(
            &asset,
            input.output.frame_bytes,
            &input.output.frame_sha256,
        )
    {
        return Err(invalid());
    }
    let bytes = wire::key_recovery_ack(&binding, &input.payload_sha256)?;
    owner.apple.input()?.current()?;
    state(&parent)?.compared.set(input).map_err(|_| invalid())?;
    Ok(bytes) // The writer still must enter and really return this exact ACK.
}

/// Normal Terminal requests pipe closure, not cancellation. This fixed
/// post-worker gate reads the original first failure and actual terminal; it
/// does not use a parsed status or STOP=false as permission for a new effect.
fn normal_terminal(inner: &Inner, owner: &Session) -> bool {
    if inner.domain != SavedCommandDomain::AppleProvisioning
        || inner.poisoned.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || Instant::now() >= owner.clocks.work
        || !owner
            .native_failure
            .try_lock()
            .is_ok_and(|first| first.is_none())
        || !matches!(&owner.context,Context::AppleProvisioning(context) if context.mode==wire::Mode::KeyRecover)
        || !owner
            .apple_key
            .get()
            .is_some_and(|parent| !parent.clock.interrupted() && !parent.clock.completed())
    {
        return false;
    }
    let registry = inner.lock();
    original_session(&registry,owner) && !registry.disabled && !registry.exhausted && !registry.stopping
        && !registry.document_lost && registry.active.as_ref().is_some_and(|active|active.accepted
            && active.terminal && !active.unknown && !active.work_expired && !active.context_invalidated
            && !active.final_join_seen && active.first_stop.is_none() && active.projection.phase==Phase::Stopping
            && active.projection.reason==Reason::None && active.projection.outcome==Some(Outcome::Complete)
            && matches!(&active.projection.result,Some(Terminal::AppleProvisioning(terminal))
                if terminal.settled() && terminal.outcome==wire::Outcome::Complete && terminal.reason==wire::Reason::None
                    && matches!(&terminal.result,Some(wire::ResultData::Key(result))
                        if result.decision==wire::KeyDecision::Compared && result.reason==wire::KeyReason::StoredKeyChecked)))
}
pub(in crate::saved_command_owner) fn post_worker_clear(
    inner: &Inner,
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    if !normal_terminal(inner, owner) {
        return Err(invalid());
    }
    let (parent, asset, loan, _) = originals(owner)?;
    let compared = state(&parent)?.compared.get().ok_or_else(invalid)?;
    if !parent.worker_joined.load(Ordering::SeqCst)
        || !owner.apple.key_recovery_returned()
        || !matches!(
            parent.phase(),
            Some(SavePhase::Waiting | SavePhase::ReturnedRefused)
        )
        || !loan.matches_public_material(&asset, compared.csr.as_bytes(), &compared.spki)
        || !loan.matches_recovery_frame(
            &asset,
            compared.output.frame_bytes,
            &compared.output.frame_sha256,
        )
    {
        return Err(invalid());
    }
    owner.apple.input()?.current()?; // OFF journal/Doc/Store guards.
    if !normal_terminal(inner, owner) {
        return Err(invalid());
    }
    Ok(())
}
pub(in crate::saved_command_owner) fn source_returned(
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    let (parent, _, _, _) = originals(owner)?;
    if !parent.worker_joined.load(Ordering::SeqCst)
        || state(&parent)?.source_checked.swap(true, Ordering::SeqCst)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Sole constructor follows actual worker/IO/source/Asset joins. It explicitly
/// excludes its own CAS and later NativeUse/private retirement from the claim.
pub(crate) struct AppleKeyRecoveryVerified {
    parent: Arc<AppleKeySession>,
    native_use: Arc<NativeUse>,
    record: KeyRecoveryRecord,
}
impl AppleKeyRecoveryVerified {
    pub(crate) fn matches(&self, native_use: &Arc<NativeUse>, record: &KeyRecoveryRecord) -> bool {
        Arc::ptr_eq(&self.native_use, native_use)
            && &self.record == record
            && self.parent.mode == wire::Mode::KeyRecover
            && self.parent.phase() == Some(SavePhase::ReturnedRefused)
            && self.parent.worker_joined.load(Ordering::SeqCst)
            && !self.parent.all_jobs_joined.load(Ordering::SeqCst)
            && !self.parent.private_drained.load(Ordering::SeqCst)
            && !self.parent.clock.interrupted()
            && self.parent.recovery.as_ref().is_some_and(|state| {
                state.issued.load(Ordering::SeqCst)
                    && state.source_checked.load(Ordering::SeqCst)
                    && state
                        .compared
                        .get()
                        .is_some_and(|input| input.output == record.output)
            })
            && self.parent.owner().is_ok_and(|owner| {
                owner.apple.key_recovery_returned()
                    && !owner.resource_unknown.load(Ordering::SeqCst)
                    && Instant::now() < owner.clocks.work
                    && owner
                        .native_failure
                        .try_lock()
                        .is_ok_and(|first| first.is_none())
            })
    }
}
pub(in crate::saved_command_owner) fn verified(
    inner: &Inner,
    owner: &Arc<Session>,
    native_use: Arc<NativeUse>,
) -> Result<(KeyRecoveryRecord, AppleKeyRecoveryVerified), BridgeError> {
    post_worker_clear(inner, owner)?;
    let (parent, _, _, binding) = originals(owner)?;
    if parent.phase() != Some(SavePhase::ReturnedRefused)
        || !state(&parent)?.source_checked.load(Ordering::SeqCst)
        || state(&parent)?.issued.swap(true, Ordering::SeqCst)
    {
        return Err(invalid());
    }
    let record = wire::key_recovery_record(&binding)?;
    let proof = AppleKeyRecoveryVerified {
        parent,
        native_use,
        record: record.clone(),
    };
    Ok((record, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> (SavedCommandOwner, Arc<Session>, wire::Terminal) {
        let context = wire::prepare(&json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,
            "keyRecordId":"d".repeat(32),"keyRecordRevision":1,"executionMode":"local","platform":"ios",
            "mode":"key-recover","reference":null,"newApplication":false,"displayName":"Explicit name"})).unwrap().context;
        let terminal = serde_json::from_value(json!({"schemaVersion":1,"context":context,
            "outcome":"complete","reason":"none","result":{"schemaVersion":1,"scope":"local-ios-distribution-key",
                "mode":"key-recover","decision":"compared","reason":"stored-key-checked",
                "saved":false,"certificateRequested":false,"credentialReady":false},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":7,
                "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}})).unwrap();
        let (application, original) = crate::saved_command_owner::tests::active_with_context(
            SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
                std::path::PathBuf::from("/unopened-key-recovery-terminal-runtime"),
            )),
            Context::AppleProvisioning(context),
        );
        super::super::initialize(&original).unwrap();
        (application, original, terminal)
    }

    #[test]
    fn recovery_normal_terminal_pipe_stop_never_substitutes_for_original_source_ack_and_joins() {
        for reason in [
            Reason::Cancelled,
            Reason::ContextChanged,
            Reason::TimedOut,
            Reason::Shutdown,
            Reason::CleanupUnknown,
        ] {
            for before_terminal in [false, true] {
                let (application, original, terminal) = session();
                let (_foreign_application, foreign, _) = session();
                let admitted = original.clocks.admitted;
                let first = admitted + Duration::from_secs(1);
                application.inner.accept_at(
                    &original,
                    Frame::AppleProvisioning(wire::Frame::Accepted),
                    admitted,
                );
                assert!(!normal_terminal(&application.inner, &original));
                if before_terminal {
                    let mut registry = application.inner.lock();
                    application
                        .inner
                        .stop_locked(&mut registry, &original, reason, first);
                }
                // Exercise actual terminal dispatch, not a fabricated stop
                // flag, NativeUse, source loan or joined worker receipt.
                application.inner.accept_at(
                    &original,
                    Frame::AppleProvisioning(wire::Frame::Terminal(terminal)),
                    admitted + Duration::from_secs(2),
                );
                assert!(*original.stop.borrow());
                assert_eq!(
                    normal_terminal(&application.inner, &original),
                    !before_terminal
                );
                assert!(!normal_terminal(&application.inner, &foreign));
                assert!(post_worker_clear(&application.inner, &original).is_err());
                assert!(!original.apple.key_recovery_returned());
                let parent = original.apple_key.get().unwrap();
                assert!(!parent.worker_joined.load(Ordering::SeqCst));
                assert!(parent.loan.get().is_none() && parent.binding.get().is_none());
                assert!(!state(parent).unwrap().issued.load(Ordering::SeqCst));
                assert!(!state(parent).unwrap().source_checked.load(Ordering::SeqCst));
                if !before_terminal {
                    assert!(parent.clock.failure().is_none());
                    let mut registry = application.inner.lock();
                    application
                        .inner
                        .stop_locked(&mut registry, &original, reason, first);
                }
                {
                    let mut registry = application.inner.lock();
                    application.inner.stop_locked(
                        &mut registry,
                        &original,
                        Reason::Shutdown,
                        admitted + Duration::from_secs(3),
                    );
                    assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(first));
                }
                assert!(!normal_terminal(&application.inner, &original));
                assert!(post_worker_clear(&application.inner, &original).is_err());
                assert_eq!(parent.clock.failure().map(|(_, at)| at), Some(first));
                assert!(
                    !parent.clock.completed() && !parent.private_drained.load(Ordering::SeqCst)
                );
            }
        }
    }
}
