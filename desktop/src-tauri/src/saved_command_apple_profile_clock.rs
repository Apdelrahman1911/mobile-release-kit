//! Clock view of the SAME admitted Apple SavedSession, never a new lifetime.
//! The Asset original borrows this exact view instead of its ordinary 10s
//! clock. First failure is latched before STOP; cleanup never renews F/W/H.
use super::*;
use crate::asset_commands::Reason as AssetReason;
use std::sync::{OnceLock, Weak};

pub(crate) struct AppleProvisioningClock {
    session: Weak<Session>,
    original: OnceLock<Weak<crate::asset_session::OriginalWork>>,
    admitted: Instant,
    work: Instant,
    hard: Instant,
    first: Mutex<Option<(AssetReason, Instant)>>,
    completed: AtomicBool,
    key_mode: bool,
    key_prepare: bool,
    key_preservation_veto: AtomicBool,
}

impl AppleProvisioningClock {
    // Only the real Start body, after retaining the SAME SavedSession and
    // before reserving/attaching its Asset destination, may construct this.
    pub(in crate::saved_command_owner) fn for_session(
        session: &Arc<Session>,
    ) -> Result<Arc<Self>, BridgeError> {
        if session.domain != SavedCommandDomain::AppleProvisioning
            || !matches!(&session.context, Context::AppleProvisioning(context) if context.mode.profile() || context.mode.key())
            || session.clocks.work <= session.clocks.admitted
            || session.clocks.cleanup < session.clocks.work
            || session.clocks.cleanup.duration_since(session.clocks.work) > SETTLEMENT
            || session.resource_unknown.load(Ordering::SeqCst)
        {
            return Err(crate::apple_provisioning_protocol::invalid());
        }
        Ok(Arc::new(Self {
            session: Arc::downgrade(session),
            original: OnceLock::new(),
            admitted: session.clocks.admitted,
            work: session.clocks.work,
            hard: session.clocks.cleanup,
            first: Mutex::new(None),
            completed: AtomicBool::new(false),
            key_mode: matches!(&session.context, Context::AppleProvisioning(context) if context.mode.key()),
            key_prepare: matches!(&session.context, Context::AppleProvisioning(context) if context.mode == crate::apple_provisioning_protocol::Mode::KeyPrepare),
            key_preservation_veto: AtomicBool::new(false),
        }))
    }

    pub(in crate::saved_command_owner) fn bind_original(
        &self,
        session: &Arc<Session>,
        original: &Arc<crate::asset_session::OriginalWork>,
    ) -> Result<(), BridgeError> {
        if !self
            .session
            .upgrade()
            .is_some_and(|same| Arc::ptr_eq(&same, session))
            || self.completed.load(Ordering::SeqCst)
            || self.first.try_lock().map_or(true, |first| first.is_some())
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.original
            .set(Arc::downgrade(original))
            .map_err(|_| BridgeError::cleanup_unknown())
    }

    pub(crate) fn work_end(&self) -> Instant {
        self.work
    }
    pub(crate) fn hard_end(&self) -> Instant {
        self.hard
    }

    pub(crate) fn failure(&self) -> Option<(AssetReason, Instant)> {
        match self.first.try_lock() {
            Ok(first) => *first,
            Err(_) => Some((AssetReason::CleanupUnknown, self.admitted)),
        }
    }

    pub(crate) fn cleanup_end(&self) -> Instant {
        self.failure().map_or(self.hard, |(_, at)| {
            at.max(self.admitted)
                .min(self.work)
                .checked_add(SETTLEMENT)
                .unwrap_or(self.hard)
                .min(self.hard)
        })
    }

    pub(crate) fn original_matches(
        &self,
        original: &Arc<crate::asset_session::OriginalWork>,
    ) -> bool {
        self.original
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|same| Arc::ptr_eq(&same, original))
    }

    /// Called by the actual Asset Work.fail while it still owns that original.
    /// No Asset/Document/Host lock is taken here. This is only failure/STOP,
    /// never a save permission, disposal receipt or native join observation.
    pub(crate) fn observe_failure_at(&self, reason: AssetReason, at: Instant) {
        self.latch(reason, at);
        if let Some(session) = self.session.upgrade() {
            let unknown = reason == AssetReason::CleanupUnknown;
            let reason = match reason {
                AssetReason::UserCancelled => Reason::Cancelled,
                AssetReason::Deadline => Reason::TimedOut,
                AssetReason::DocumentLost => Reason::DocumentLost,
                AssetReason::Shutdown if self.key_mode => Reason::Shutdown,
                AssetReason::CleanupUnknown => Reason::CleanupUnknown,
                _ => Reason::CredentialsUnavailable,
            };
            // No profile callback from observe_failure_at: this cannot relock
            // the Asset vault Work that reported the first native failure.
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            session.observe_failure_at(reason, at, unknown);
            #[cfg(not(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )))]
            {
                let _ = (reason, at);
                if unknown {
                    session.resource_unknown.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    pub(in crate::saved_command_owner) fn latch(&self, reason: AssetReason, at: Instant) {
        // A later excluded failure vetoes local-key preservation even when an
        // earlier cancellation remains the displayed first reason. Never
        // overwrite/forget that later loss through the minimum-F projection.
        if self.key_mode
            && !matches!(
                reason,
                AssetReason::UserCancelled | AssetReason::Shutdown | AssetReason::Deadline
            )
        {
            self.key_preservation_veto.store(true, Ordering::SeqCst);
        }
        match self.first.try_lock() {
            Ok(mut first) => {
                if first.is_none_or(|(_, earlier)| at < earlier) {
                    *first = Some((reason, at));
                }
            }
            Err(_) => {
                if let Some(session) = self.session.upgrade() {
                    session.resource_unknown.store(true, Ordering::SeqCst);
                }
            }
        }
        if self.key_mode {
            if let Some(session) = self.session.upgrade() {
                session.apple.changed.notify_waiters();
            }
        }
        // Failure on the Saved original must wake its SAME Asset original.
        // This only requests STOP; it cannot acknowledge source/save closure.
        if let Some(original) = self.original.get().and_then(Weak::upgrade) {
            original.request_apple_profile_stop();
        }
    }

    /// Memory-only key-prepare tail. It is NOT a fresh admission and never
    /// authorizes generation, Pending/GO, certificate POST or profile save.
    /// Every original native source/Store check remains independently required.
    pub(crate) fn key_preservation_end(&self) -> Option<Instant> {
        if !self.key_prepare
            || self.completed.load(Ordering::SeqCst)
            || self.key_preservation_veto.load(Ordering::SeqCst)
            || self
                .session
                .upgrade()
                .is_none_or(|session| session.resource_unknown.load(Ordering::SeqCst))
        {
            return None;
        }
        let first = self.first.try_lock().ok()?;
        let end = match *first {
            None => self.work,
            Some((
                AssetReason::UserCancelled | AssetReason::Shutdown | AssetReason::Deadline,
                at,
            )) => at
                .max(self.admitted)
                .min(self.work)
                .checked_add(SETTLEMENT)?
                .min(self.hard),
            _ => return None,
        };
        (Instant::now() < end).then_some(end)
    }

    pub(crate) fn interrupted(&self) -> bool {
        !self.completed.load(Ordering::SeqCst)
            && (Instant::now() >= self.work
                || self.failure().is_some()
                || self
                    .session
                    .upgrade()
                    .is_none_or(|session| session.resource_unknown.load(Ordering::SeqCst)))
    }

    // Only after real private disposal, all source/worker/journal/native-use
    // and Asset continuation returns. Normal terminal pipe STOP is NOT this.
    pub(in crate::saved_command_owner) fn mark_completed(&self, session: &Arc<Session>) -> bool {
        if !self
            .session
            .upgrade()
            .is_some_and(|same| Arc::ptr_eq(&same, session))
            || session.resource_unknown.load(Ordering::SeqCst)
        {
            return false;
        }
        self.completed.store(true, Ordering::SeqCst);
        true
    }

    pub(crate) fn completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()
    }
}
