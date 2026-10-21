//! Closed foreground HISTORY policy. This is not a project/Document witness or
//! a grant: the original native Host must still acquire, recheck and publish.
//! Kept independent of native modules so the existing client graph stays small.
use super::*;

pub(crate) const HISTORY_STARTUP_WORK: Duration = Duration::from_secs(30);
pub(crate) struct HistoryLease {
    started: Instant,
    expires: Instant,
    startup_expires: Instant,
    stopped: AtomicBool,
}
impl HistoryLease {
    pub(crate) fn new(started: Instant, lifetime: Duration) -> Result<Arc<Self>, Error> {
        if lifetime.is_zero() || lifetime > MAX_ACCESS {
            return Err(Error::InvalidRequest);
        }
        let expires = started.checked_add(lifetime).ok_or(Error::InvalidRequest)?;
        Ok(Arc::new(Self {
            started,
            expires,
            startup_expires: started
                .checked_add(HISTORY_STARTUP_WORK)
                .ok_or(Error::InvalidRequest)?
                .min(expires),
            stopped: AtomicBool::new(false),
        }))
    }
    pub(crate) fn started(&self) -> Instant {
        self.started
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn startup_expires(&self) -> Instant {
        self.startup_expires
    }
    /// Called BEFORE any potentially blocking Host/Service/Store cleanup.
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        if Instant::now() >= self.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }
    /// Only the one initial grant publication uses the shorter work deadline.
    /// A late blocked publication fences the entire original, not a new lease.
    pub(super) fn publication_current(&self) -> Result<(), Error> {
        self.current()?;
        if Instant::now() >= self.startup_expires {
            self.stop();
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// No action, proposal, scope discovery or live DATA-cell route belongs here.
/// Check BEFORE the original dispatcher's special-case early returns.
pub(super) fn history_request(request: &p::RequestBody) -> bool {
    matches!(
        request,
        p::RequestBody::Info(_)
            | p::RequestBody::Projects(_)
            | p::RequestBody::Observe(_)
            | p::RequestBody::Operations(_)
            | p::RequestBody::Operation(_)
    )
}

impl ApplicationService {
    pub(crate) fn open_history(
        store: Arc<PrivateStateDirectory>,
        lease: Arc<HistoryLease>,
    ) -> Result<Self, Error> {
        lease.current()?;
        let mut service = Self::open(store)?;
        // The service has not been published/listened to. Ordinary constructors
        // remain Desktop mode; no request can switch this immutable policy.
        service.history_lease = Some(lease);
        service.native_history_current()?;
        Ok(service)
    }
    pub(crate) fn allow_history_read(
        &self,
        project: Id,
        lease: &Arc<HistoryLease>,
    ) -> Result<ReadAccessStatus, Error> {
        if !self
            .history_lease
            .as_ref()
            .is_some_and(|original| Arc::ptr_eq(original, lease))
        {
            return Err(Error::AccessDenied);
        }
        lease.publication_current()?;
        self.allow_read_inner(vec![project], None)
    }
    pub(super) fn read_publication_current(&self) -> Result<(), Error> {
        self.native_history_current()?;
        if let Some(original) = &self.history_lease {
            original.publication_current()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_history_lease_never_renews_or_rearms() {
        let start = Instant::now() - Duration::from_secs(20);
        let lease = HistoryLease::new(start, Duration::from_secs(30)).unwrap();
        assert_eq!(lease.expires(), start + Duration::from_secs(30));
        assert_eq!(lease.started(), start);
        assert_eq!(lease.startup_expires(), lease.expires());
        assert!(lease.current().is_ok());
        lease.stop();
        assert_eq!(lease.current(), Err(Error::AccessDenied));
        assert_eq!(lease.expires(), start + Duration::from_secs(30));
        let expired = HistoryLease::new(start, Duration::from_secs(1)).unwrap();
        assert_eq!(expired.current(), Err(Error::Expired));
        let work_expired =
            HistoryLease::new(Instant::now() - Duration::from_secs(31), MAX_ACCESS).unwrap();
        assert_eq!(
            work_expired.startup_expires(),
            work_expired.started() + HISTORY_STARTUP_WORK
        );
        assert!(work_expired.current().is_ok());
        assert_eq!(work_expired.publication_current(), Err(Error::Expired));
        assert_eq!(work_expired.current(), Err(Error::AccessDenied));
        assert!(HistoryLease::new(start, Duration::ZERO).is_err());
        assert!(HistoryLease::new(start, MAX_ACCESS + Duration::from_secs(1)).is_err());
    }
}

#[cfg(test)]
#[path = "application_service_history_tests.rs"]
mod service_tests;
