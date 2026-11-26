//! Cleanup-only companion of the original GenerateUploadKey owner.
//!
//! This is a child of the private binary receiver, not a new runner or a
//! terminal-to-success conversion. No cancellation fact can create a candidate.
use super::*;

#[derive(Default)]
pub(in crate::saved_command_owner) struct CancellationState {
    no_go: Mutex<Option<NoGoCloseDisposition>>,
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    disposal: Mutex<Option<crate::asset_session::UploadKeyCancellationDisposal>>,
}

// Retained before the existing native-observation/SH-close path. This only
// explains an intentionally unsent private frame; it does not certify a join.
struct NoGoCloseDisposition {
    original: Weak<Session>,
    preparation: Weak<UploadKeyPreparation>,
}
impl NoGoCloseDisposition {
    fn matches(&self, owner: &Session, preparation: &Arc<UploadKeyPreparation>) -> bool {
        self.original
            .upgrade()
            .is_some_and(|original| std::ptr::eq(&*original, owner))
            && self
                .preparation
                .upgrade()
                .is_some_and(|original| Arc::ptr_eq(&original, preparation))
    }
}

fn unclaimed(writer: Option<&PrivateUploadKeyInput>) -> bool {
    writer.is_some_and(|writer| unclaimed_flags(writer.send_claimed, writer.sent))
}
fn unclaimed_flags(claimed: bool, sent: bool) -> bool {
    !claimed && !sent
}
fn cancelled_header(backing: &Backing) -> bool {
    backing.eof
        && backing.length == wire::READY_LENGTH + wire::END_HEADER_LENGTH
        && backing.target == backing.length
        && backing.header.is_some_and(|header| {
            header.status == wire::CoreStatus::Cancelled
                && header.jks == 0
                && header.certificate == 0
        })
}
fn write_refusal(end: &WriteEnd) -> bool {
    end.sent && end.closed && end.failed
}
fn preparation_session_matches(preparation: &UploadKeyPreparation, owner: &Session) -> bool {
    preparation.session.try_lock().is_ok_and(|slot| {
        slot.as_ref().is_some_and(|original| {
            original
                .upgrade()
                .is_some_and(|same| std::ptr::eq(&*same, owner))
        })
    }) && preparation.id == owner.id
        && preparation.generation == owner.generation
        && matches!(&owner.context, Context::GenerateUploadKey(context) if context == &preparation.context)
        && preparation.registration == owner.registration
        && preparation.root == owner.project
}

/// The writer may observe a genuine parent Cancel before the parent's async
/// wait loop forwards it. Keep that original cause/time instead of letting a
/// later CommandIncomplete win solely because of task scheduling.
pub(in crate::saved_command_owner) fn private_write_failed(inner: &Inner, owner: &Session) {
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if owner.domain == SavedCommandDomain::GenerateUploadKey {
        let original = (|| {
            let intent = owner.upload_key.intent.as_ref()?;
            if !preparation_session_matches(&intent.preparation, owner) {
                return None;
            }
            let writer = owner.upload_key.writer.try_lock().ok()?;
            if !unclaimed(writer.as_ref())
                || writer
                    .as_ref()
                    .is_none_or(|writer| !Arc::ptr_eq(&writer.preparation, &intent.preparation))
            {
                return None;
            }
            let gate = intent.gate.try_lock().ok()?;
            gate.as_ref()?.cancelled_no_go_failure(&intent.preparation)
        })();
        if let Some(first) = original {
            let mut registry = inner.lock();
            inner.stop_locked(&mut registry, owner, Reason::Cancelled, first);
            return;
        }
    }
    inner.stop(owner, Reason::CommandIncomplete);
}

/// Called with the ORIGINAL resource/startup/registry borrows already held.
/// No registry re-lock, Doc/Store IO or native operation is performed here.
/// Both native_consumers_returned and observe_final use this SAME disposition.
pub(in crate::saved_command_owner) fn cancelled_no_go_writer(
    owner: &Session,
    active: &Active,
    book: &Resources,
) -> bool {
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (owner, active, book);
        false
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        if owner.domain != SavedCommandDomain::GenerateUploadKey
            || !std::ptr::eq(&*active.owner, owner)
            || active.unknown
            || active.context_invalidated
            || active.first_stop.is_none()
            || active.projection.reason != Reason::Cancelled
            || !active.accepted
            || !active.terminal
            || !matches!(active.projection.result.as_ref(), Some(Terminal::GenerateUploadKey(terminal))
                if terminal.status == wire::CoreStatus::Cancelled)
            || owner.resource_unknown.load(Ordering::SeqCst)
            || book.writer.is_some()
            || book.stdout.is_some()
            || book.stderr.is_some()
            || book.write_failed
            || book.out_failed
            || book.err_failed
            || !book.write_end.as_ref().is_some_and(write_refusal)
            || !book.out_end.as_ref().is_some_and(|end| {
                end.closed && end.eof && end.protocol_settled_for(&owner.context)
            })
            || !book
                .err_end
                .as_ref()
                .is_some_and(|end| end.closed && end.eof && !end.failed && end.frames == 0)
        {
            return false;
        }
        let state = &owner.upload_key;
        let Some(intent) = &state.intent else {
            return false;
        };
        if !preparation_session_matches(&intent.preparation, owner) {
            return false;
        }
        let Some(receive) = &state.receive else {
            return false;
        };
        if !receive.ready.load(Ordering::SeqCst)
            || !receive.complete.load(Ordering::SeqCst)
            || state.disposed.load(Ordering::SeqCst)
        {
            return false;
        }
        let Ok(writer) = state.writer.try_lock() else {
            return false;
        };
        if !unclaimed(writer.as_ref())
            || writer
                .as_ref()
                .is_none_or(|writer| !Arc::ptr_eq(&writer.preparation, &intent.preparation))
        {
            return false;
        }
        let Ok(backing) = receive.backing.try_lock() else {
            return false;
        };
        if !cancelled_header(&backing)
            || !state
                .candidate
                .try_lock()
                .is_ok_and(|candidate| candidate.is_none())
        {
            return false;
        }
        let Ok(gate) = intent.gate.try_lock() else {
            return false;
        };
        if !gate
            .as_ref()
            .is_some_and(|gate| gate.cancelled_no_go_origin(&intent.preparation))
        {
            return false;
        }
        let Ok(mut retained) = state.cancellation.no_go.try_lock() else {
            return false;
        };
        if let Some(proof) = retained.as_ref() {
            return proof.matches(owner, &intent.preparation);
        }
        *retained = Some(NoGoCloseDisposition {
            original: Arc::downgrade(&active.owner),
            preparation: Arc::downgrade(&intent.preparation),
        });
        true
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    NoGo,
    Saved(
        crate::vault_format::Identity,
        crate::vault_format::Id,
        crate::vault_format::Revision,
    ),
}

/// Non-Clone original native quorum, minted only AFTER the existing actual
/// observer/driver/manager/SH-tail joins. It cannot publish, Bind or regenerate.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
pub(crate) struct UploadKeyCancelledNative {
    original: Weak<Session>,
    preparation: Weak<UploadKeyPreparation>,
    target: Target,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
impl UploadKeyRun {
    fn cancellation_target(&self, target: Target) -> bool {
        let owner = &self.session;
        let state = &owner.upload_key;
        if !original_joined(owner)
            || !state.final_seen.load(Ordering::SeqCst)
            || state.disposed.load(Ordering::SeqCst)
        {
            return false;
        }
        let Some(intent) = &state.intent else {
            return false;
        };
        let Some(receive) = &state.receive else {
            return false;
        };
        let Ok(writer) = state.writer.try_lock() else {
            return false;
        };
        let Ok(candidate) = state.candidate.try_lock() else {
            return false;
        };
        match target {
            Target::NoGo => {
                unclaimed(writer.as_ref())
                    && candidate.is_none()
                    && state.cancellation.no_go.try_lock().is_ok_and(|proof| {
                        proof
                            .as_ref()
                            .is_some_and(|proof| proof.matches(owner, &intent.preparation))
                    })
                    && receive.ready.load(Ordering::SeqCst)
                    && receive.complete.load(Ordering::SeqCst)
                    && receive
                        .backing
                        .try_lock()
                        .is_ok_and(|backing| cancelled_header(&backing))
            }
            Target::Saved(vault, record, revision) => {
                writer
                    .as_ref()
                    .is_some_and(|writer| writer.send_claimed && writer.sent)
                    && candidate.as_ref().is_some_and(|candidate| {
                        // Not candidate.current(): the intentional parent STOP
                        // invalidates new use, not earlier authenticated readback.
                        candidate
                            .original
                            .upgrade()
                            .is_some_and(|same| Arc::ptr_eq(&same, owner))
                            && candidate.context.vault == vault
                            && candidate.context.record == record
                            && candidate.seal_attempted
                            && candidate.authenticated
                            && candidate.sealed_revision == Some(revision)
                            && Arc::ptr_eq(&candidate.book, receive)
                            && receive.joined.load(Ordering::SeqCst)
                            && receive.complete.load(Ordering::SeqCst)
                            && receive.backing.try_lock().is_ok_and(|backing| {
                                backing.eof
                                    && backing
                                        .header
                                        .is_some_and(|header| header.status == wire::CoreStatus::Ok)
                            })
                    })
            }
        }
    }

    // Read-only pending-cleanup observation. A true value cannot create the
    // disposal below, erase Unknown or skip the later durable journal check.
    pub(crate) fn cancelled_no_go_settled(&self) -> bool {
        self.cancellation_target(Target::NoGo)
    }
    pub(crate) fn cancelled_saved_settled(
        &self,
        vault: crate::vault_format::Identity,
        record: crate::vault_format::Id,
        revision: crate::vault_format::Revision,
    ) -> bool {
        self.cancellation_target(Target::Saved(vault, record, revision))
    }

    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn cancelled_original(
        &self,
        parent: &crate::asset_session::OriginalWork,
        saved: Option<(
            crate::vault_format::Identity,
            crate::vault_format::Id,
            crate::vault_format::Revision,
        )>,
    ) -> Result<UploadKeyCancelledNative, BridgeError> {
        let intent = self
            .session
            .upload_key
            .intent
            .as_ref()
            .ok_or_else(wire::invalid)?;
        let gate = intent.gate()?;
        let target = saved.map_or(Target::NoGo, |(vault, record, revision)| {
            Target::Saved(vault, record, revision)
        });
        if !gate.matches_original(parent)
            || !gate.cancelled_origin(&intent.preparation)
            || !self.cancellation_target(target)
        {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(UploadKeyCancelledNative {
            original: Arc::downgrade(&self.session),
            preparation: Arc::downgrade(&intent.preparation),
            target,
        })
    }

    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn dispose_cancelled(
        &self,
        proof: crate::asset_session::UploadKeyCancellationDisposal,
    ) -> Result<(), BridgeError> {
        let state = &self.session.upload_key;
        let mut retained = state
            .cancellation
            .disposal
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if retained.is_some() || state.disposed.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        *retained = Some(proof); // Retain BEFORE checking/consuming; no retry on uncertainty.
        let result = (|| {
            let intent = state.intent.as_ref().ok_or_else(wire::invalid)?;
            let proof = retained.as_mut().ok_or_else(wire::invalid)?;
            if !proof.matches(self, &intent.preparation)
                || !original_joined(&self.session)
                || !state
                    .disposal
                    .try_lock()
                    .is_ok_and(|positive| positive.is_none())
            {
                return Err(BridgeError::cleanup_unknown());
            }
            let receive = state.receive.as_ref().ok_or_else(wire::invalid)?;
            let mut bytes = receive
                .backing
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut writer = state
                .writer
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut candidate = state
                .candidate
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut gate = intent
                .gate
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            // `matches` above checked the full original candidate/writer BEFORE
            // taking those same slots. Consume only immutable identity here.
            proof
                .consume(&intent.preparation)
                .map_err(|_| BridgeError::cleanup_unknown())?;
            bytes.bytes.zeroize();
            bytes.length = 0;
            bytes.target = 0;
            bytes.header = None;
            if let Some(writer) = writer.as_mut() {
                writer.bytes.zeroize();
                writer.go.take();
            }
            writer.take();
            candidate.take();
            gate.take();
            state.disposed.store(true, Ordering::SeqCst);
            Ok(())
        })();
        if result.is_err() {
            state.invalid.store(true, Ordering::SeqCst);
            self.session.resource_unknown.store(true, Ordering::SeqCst);
        }
        result
    }

    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn cancelled_private_disposed(
        &self,
        parent: &crate::asset_session::OriginalWork,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> bool {
        let state = &self.session.upload_key;
        state.disposed.load(Ordering::SeqCst)
            && original_joined(&self.session)
            && state.cancellation.disposal.try_lock().is_ok_and(|proof| {
                proof
                    .as_ref()
                    .is_some_and(|proof| proof.consumed_for(parent, preparation))
            })
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
impl UploadKeyCancelledNative {
    pub(crate) fn matches(
        &self,
        run: &UploadKeyRun,
        preparation: &Arc<UploadKeyPreparation>,
    ) -> bool {
        self.original
            .upgrade()
            .is_some_and(|same| Arc::ptr_eq(&same, &run.session))
            && self
                .preparation
                .upgrade()
                .is_some_and(|same| Arc::ptr_eq(&same, preparation))
            && run.cancellation_target(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intentional_private_refusal_is_not_an_unsent_or_unclosed_outer_request() {
        assert!(write_refusal(&WriteEnd {
            sent: true,
            closed: true,
            failed: true
        }));
        for end in [
            WriteEnd {
                sent: false,
                closed: true,
                failed: true,
            },
            WriteEnd {
                sent: true,
                closed: false,
                failed: true,
            },
            WriteEnd {
                sent: true,
                closed: true,
                failed: false,
            },
        ] {
            assert!(!write_refusal(&end));
        }
    }
    #[test]
    fn absent_private_writer_does_not_prove_no_go() {
        assert!(!unclaimed(None));
    }
    #[test]
    fn claiming_even_an_unflushed_private_write_blocks_no_go() {
        assert!(unclaimed_flags(false, false));
        for (claimed, sent) in [(true, false), (true, true), (false, true)] {
            assert!(!unclaimed_flags(claimed, sent));
        }
    }
    #[test]
    fn ready_or_partial_result_is_not_a_cancelled_terminal() {
        let receive = ReceiveBook::reserved().unwrap();
        let mut backing = receive.backing.try_lock().unwrap();
        assert!(!cancelled_header(&backing));
        backing.eof = true;
        assert!(!cancelled_header(&backing));
        // Receiver allocation and EOF are inert DATA, not an original join or
        // an exception at either real native-settlement gate.
        assert!(!receive.joined.load(Ordering::SeqCst));
    }
    #[test]
    fn only_exact_empty_cancelled_terminal_can_explain_private_refusal() {
        let receive = ReceiveBook::reserved().unwrap();
        let mut backing = receive.backing.try_lock().unwrap();
        backing.eof = true;
        backing.length = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
        backing.target = backing.length;
        for status in [
            wire::CoreStatus::Ok,
            wire::CoreStatus::Refused,
            wire::CoreStatus::TimedOut,
            wire::CoreStatus::CleanupUnknown,
        ] {
            backing.header = Some(wire::EndHeader {
                status,
                jks: 0,
                certificate: 0,
            });
            assert!(!cancelled_header(&backing));
        }
        backing.header = Some(wire::EndHeader {
            status: wire::CoreStatus::Cancelled,
            jks: 0,
            certificate: 0,
        });
        assert!(cancelled_header(&backing));
        backing.header.as_mut().unwrap().jks = 1;
        assert!(!cancelled_header(&backing));
        backing.header.as_mut().unwrap().jks = 0;
        backing.eof = false;
        assert!(!cancelled_header(&backing));
        assert!(!receive.joined.load(Ordering::SeqCst));
    }
}
