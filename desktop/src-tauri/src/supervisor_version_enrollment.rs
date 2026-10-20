//! Enrollment uses the SAME Setup bootstrap/installed Book and the existing
//! Supervisor READY/GO/EOF, IO, driver/watchdog and native settlement owners.
//! This child adds one typed arm, not a transport, subprocess or state writer.
use super::*;
use crate::version_enrollment_protocol as p;
use std::sync::Weak;

pub(crate) struct VersionEnrollmentControl {
    stopped: AtomicBool,
    unknown: AtomicBool,
    live: AtomicBool,
    original: Mutex<Option<Weak<Owner>>>,
    cleanup_cutoff: watch::Sender<Option<Instant>>,
}
impl VersionEnrollmentControl {
    pub(crate) fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
            live: AtomicBool::new(true),
            original: Mutex::new(None),
            cleanup_cutoff: watch::channel(None).0,
        }
    }
    pub(crate) fn current(&self) -> bool {
        self.live.load(Ordering::SeqCst)
            && !self.stopped.load(Ordering::SeqCst)
            && !self.unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn pending(&self) -> bool {
        self.live.load(Ordering::SeqCst) || self.unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn uncertain(&self) -> bool {
        self.unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn stop(&self) {
        self.stop_at(Instant::now());
    }
    /// The actual failing job samples F before returning to an async observer.
    /// Keep an absolute endpoint so a native cutoff never needs reconstructing
    /// from a later notification, and every subsequent observation only mins it.
    pub(crate) fn stop_at(&self, detected_at: Instant) {
        let end = match detected_at.checked_add(CLEANUP_TIME) {
            Some(end) => end,
            None => {
                self.unknown.store(true, Ordering::SeqCst);
                detected_at
            }
        };
        self.retain_cleanup_endpoint(end);
        // Recover only to STOP the same original; poison never grants closure.
        let original = match self.original.lock() {
            Ok(v) => v,
            Err(e) => {
                self.unknown.store(true, Ordering::SeqCst);
                e.into_inner()
            }
        };
        let owner = original.as_ref().and_then(Weak::upgrade);
        drop(original);
        if let Some(owner) = owner {
            let mut state = match owner.state.lock() {
                Ok(v) => v,
                Err(e) => {
                    self.unknown.store(true, Ordering::SeqCst);
                    e.into_inner()
                }
            };
            if !state.terminal {
                state.fail_at(p::refused(p::Reason::Cancelled), detected_at);
            }
            let original_end = state.cleanup_endpoint;
            drop(state);
            if let Some(end) = original_end {
                self.retain_cleanup_endpoint(end);
            }
            owner.stop.send_replace(true);
            owner.changed.notify_waiters();
        }
    }
    /// The SAME Supervisor retirement supplies its original cutoff after
    /// releasing OwnerState. This must not call back into Owner/failure.
    fn retain_cleanup_endpoint(&self, end: Instant) {
        self.stopped.store(true, Ordering::SeqCst);
        self.cleanup_cutoff.send_if_modified(|current| {
            if current.is_some_and(|old| old <= end) {
                false
            } else {
                *current = Some(end);
                true
            }
        });
    }
    pub(crate) fn unknown(&self) {
        self.unknown.store(true, Ordering::SeqCst);
        self.stop();
    }
    pub(crate) fn never_admitted(&self) -> bool {
        !self.uncertain() && self.original.lock().is_ok_and(|v| v.is_none())
    }
    pub(crate) fn stop_clock(&self) -> watch::Receiver<Option<Instant>> {
        self.cleanup_cutoff.subscribe()
    }
    pub(crate) fn cleanup_end(&self, work_end: Instant) -> Option<Instant> {
        let hard = work_end.checked_add(CLEANUP_TIME)?;
        Some((*self.cleanup_cutoff.borrow()).map_or(hard, |end| end.min(hard)))
    }
    pub(crate) fn check_cleanup(&self, work_end: Instant) -> Result<(), BridgeError> {
        if self.uncertain()
            || self.cleanup_end(work_end).is_none_or(|end| Instant::now() >= end)
        {
            self.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(())
    }
    /// Original Document calls only after known nonentry OR actual HTTP and
    /// every native state-job return. No Drop/status/FIN calls this method.
    pub(crate) fn returned(&self, work_end: Instant) -> Result<(), BridgeError> {
        self.check_cleanup(work_end)?;
        if !self.live.swap(false, Ordering::SeqCst) {
            self.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        // Unknown keeps pending true even if the original live bit just moved.
        // A simultaneous earlier STOP/deadline cannot grant returned credit.
        self.check_cleanup(work_end)
    }
    fn arm(&self, owner: &Arc<Owner>) -> Result<(), BridgeError> {
        let mut original = self
            .original
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if original.is_some() || !self.current() {
            return Err(p::refused(p::Reason::Cancelled));
        }
        *original = Some(Arc::downgrade(owner));
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub(crate) enum VersionEnrollmentReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(super) struct Invocation {
    pub(super) request: Arc<p::Request>,
    pub(super) gate: crate::asset_session::VersionEnrollmentGoGate,
    pub(super) control: Arc<VersionEnrollmentControl>,
    mailbox: Mutex<VersionEnrollmentReceipt>,
    observer: gh_auth::FinalObserverReturn,
    waiting: AtomicBool,
}
impl Invocation {
    pub(super) fn arm(&self, owner: &Arc<Owner>) -> Result<(), BridgeError> {
        self.control.arm(owner)
    }
    pub(super) fn unknown(&self) {
        self.control.unknown();
        if let Ok(mut value) = self.mailbox.lock() {
            if matches!(*value, VersionEnrollmentReceipt::Pending) {
                *value = VersionEnrollmentReceipt::RetainedUnknown;
            }
        }
    }
    pub(super) fn retire(
        &self,
        outcome: Result<p::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
        cleanup_endpoint: Option<Instant>,
    ) {
        if let Some(end) = cleanup_endpoint {
            self.control.retain_cleanup_endpoint(end);
        }
        let Ok(mut value) = self.mailbox.lock() else {
            self.control.unknown();
            return;
        };
        let was_unknown = was_unknown
            || self.control.uncertain()
            || matches!(*value, VersionEnrollmentReceipt::RetainedUnknown);
        if !matches!(*value, VersionEnrollmentReceipt::Settled { .. }) {
            *value = VersionEnrollmentReceipt::Settled {
                outcome: if was_unknown {
                    Err(BridgeError::cleanup_unknown())
                } else {
                    outcome
                },
                settled_at,
                was_unknown,
            };
        }
    }
    fn receipt(&self) -> VersionEnrollmentReceipt {
        if self.control.uncertain() {
            return VersionEnrollmentReceipt::RetainedUnknown;
        }
        match self.mailbox.lock() {
            Ok(v) => v.clone(),
            Err(_) => VersionEnrollmentReceipt::RetainedUnknown,
        }
    }
}
pub(crate) struct VersionEnrollmentAdmission {
    pub(super) invocation: Arc<Invocation>,
    pub(super) work_end: Instant,
}
impl VersionEnrollmentAdmission {
    pub(crate) fn new(
        request: Arc<p::Request>,
        gate: crate::asset_session::VersionEnrollmentGoGate,
        control: Arc<VersionEnrollmentControl>,
        work_end: Instant,
    ) -> Result<Self, BridgeError> {
        p::need(
            request.valid()
                && control.current()
                && control.never_admitted()
                && work_end > Instant::now()
                && work_end <= Instant::now() + Duration::from_secs(60),
        )?;
        p::encode_initial("version-enrollment-18446744073709551615", &request)?;
        Ok(Self {
            invocation: Arc::new(Invocation {
                request,
                gate,
                control,
                mailbox: Mutex::new(VersionEnrollmentReceipt::Pending),
                observer: gh_auth::FinalObserverReturn::new(),
                waiting: AtomicBool::new(false),
            }),
            work_end,
        })
    }
}
pub(crate) struct VersionEnrollmentTicket {
    owner: Arc<Owner>,
    original: Arc<Invocation>,
}
impl VersionEnrollmentTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn receipt(&self) -> VersionEnrollmentReceipt {
        self.original.receipt()
    }
    pub(crate) fn wait_original(&self) -> VersionEnrollmentWait {
        VersionEnrollmentWait {
            owner: self.owner.clone(),
            original: self.original.clone(),
        }
    }
}
/// Only an ACTUAL successful original observer join constructs this value.
/// A failed/refused read can be settled too; it cannot supply an enrollment.
pub(crate) struct VersionEnrollmentJoined {
    original: Arc<Invocation>,
    outcome: Result<p::Reply, BridgeError>,
    settled_at: Instant,
}
impl VersionEnrollmentJoined {
    pub(crate) fn request(&self) -> &Arc<p::Request> {
        &self.original.request
    }
    pub(crate) fn outcome(&self) -> &Result<p::Reply, BridgeError> {
        &self.outcome
    }
    pub(crate) fn settled_at(&self) -> Instant {
        self.settled_at
    }
    pub(crate) fn matches(
        &self,
        control: &Arc<VersionEnrollmentControl>,
        request: &Arc<p::Request>,
    ) -> bool {
        Arc::ptr_eq(&self.original.control, control) && Arc::ptr_eq(&self.original.request, request)
    }
}
pub(crate) struct VersionEnrollmentWait {
    owner: Arc<Owner>,
    original: Arc<Invocation>,
}
struct Waiting<'a> {
    original: &'a Invocation,
    returned: bool,
}
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if !self.returned {
            self.original.unknown();
        }
    }
}
impl VersionEnrollmentWait {
    pub(crate) async fn returned(self) -> Result<VersionEnrollmentJoined, BridgeError> {
        if self.original.waiting.swap(true, Ordering::SeqCst) {
            self.original.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        let mut guard = Waiting {
            original: &self.original,
            returned: false,
        };
        loop {
            let changed = self.owner.changed.notified();
            match self.original.receipt() {
                VersionEnrollmentReceipt::Pending => changed.await,
                VersionEnrollmentReceipt::RetainedUnknown
                | VersionEnrollmentReceipt::Settled {
                    was_unknown: true, ..
                } => return Err(BridgeError::cleanup_unknown()),
                VersionEnrollmentReceipt::Settled {
                    outcome,
                    settled_at,
                    was_unknown: false,
                } => {
                    if !self.original.observer.join_original(&self.owner).await {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    guard.returned = true;
                    return Ok(VersionEnrollmentJoined {
                        original: self.original.clone(),
                        outcome,
                        settled_at,
                    });
                }
            }
        }
    }
}
impl Supervisor {
    pub(crate) fn version_enrollment_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_version_enrollment(
        &self,
        admission: VersionEnrollmentAdmission,
    ) -> Result<VersionEnrollmentTicket, BridgeError> {
        if !self.version_enrollment_available() {
            return Err(p::refused(p::Reason::RuntimeUnavailable));
        }
        let original = admission.invocation.clone();
        let owner = self.admit(
            AdmissionRequest::VersionEnrollment(admission),
            CompletionTarget::VersionEnrollment,
        )?;
        Ok(VersionEnrollmentTicket { owner, original })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_and_poison_keep_original_pending_not_a_returned_credit() {
        let end = Instant::now() + Duration::from_secs(60);
        let control = Arc::new(VersionEnrollmentControl::new());
        assert!(control.never_admitted());
        control.stop();
        assert!(!control.current());
        assert!(control.pending());
        control.returned(end).unwrap();
        assert!(!control.pending());
        assert!(control.returned(end).is_err());
        assert!(control.pending());
        let control = Arc::new(VersionEnrollmentControl::new());
        let poison = control.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = poison.original.lock().unwrap();
            panic!("inert bookkeeping poison")
        });
        control.stop();
        assert!(control.uncertain());
        assert!(!control.never_admitted());
        assert!(control.returned(end).is_err());
    }
    #[test]
    fn native_cutoff_and_original_job_failure_only_contract_cleanup() {
        let now = Instant::now();
        let work_end = now + Duration::from_secs(60);
        let control = VersionEnrollmentControl::new();
        control.stop_at(now);
        let native_end = now + Duration::from_millis(500);
        control.retain_cleanup_endpoint(native_end);
        assert_eq!(control.cleanup_end(work_end), Some(native_end));
        // Delayed finish/STOP and later native observations cannot renew F.
        control.stop_at(now + Duration::from_secs(1));
        control.retain_cleanup_endpoint(now + Duration::from_secs(3));
        assert_eq!(control.cleanup_end(work_end), Some(native_end));
        assert!(control.pending());
        assert!(!control.current());
        assert!(!control.uncertain());
    }
    #[test]
    fn delayed_original_return_keeps_unknown_and_cannot_release_the_lane() {
        let now = Instant::now();
        let work_end = now + Duration::from_secs(60);
        let control = VersionEnrollmentControl::new();
        // Exact original cutoff, not receipt-time plus a new grace interval.
        control.retain_cleanup_endpoint(now);
        assert!(control.returned(work_end).is_err());
        assert!(control.uncertain());
        assert!(control.pending());
        assert!(!control.never_admitted());
        control.stop();
        assert_eq!(control.cleanup_end(work_end), Some(now));
        assert!(control.returned(work_end).is_err());
    }
}
