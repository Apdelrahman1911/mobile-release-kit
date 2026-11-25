//! ONE explicit foreground history admission on the existing Host. No Document
//! identity, saved-edit stamp, snapshot, runtime or execution grant is created.
use super::*;
use crate::application_service::HistoryLease;
use std::sync::atomic::Ordering;

const ALIAS: &str = "headless-history";
// Three bounded SourceBooks (PRE, existing application exclusion, POST), one
// selected path/registration and their finite ancestry/name rosters. Service
// frames and persisted state keep their separate existing quotas.
const SOURCE_CONTROL_BYTES: usize = 1024 * 1024;

pub(super) struct Sources {
    pre: SourceBook,
    post: SourceBook,
    proof: Option<ProjectProbe>,
    post_proof: Option<ProjectProbe>,
}
impl Sources {
    fn new() -> Self {
        Self {
            pre: SourceBook::new(),
            post: SourceBook::new(),
            proof: None,
            post_proof: None,
        }
    }
    pub(super) fn retire(&mut self) -> bool {
        // Bitwise combination deliberately attempts BOTH independent closes.
        self.pre.retire_application_probe() & self.post.retire_application_probe()
    }
    fn settled(&self) -> bool {
        self.pre.settled() && self.post.settled()
    }
    fn bytes(&self) -> Option<usize> {
        self.pre
            .retained_bytes()?
            .checked_add(self.post.retained_bytes()?)?
            .checked_add(16 * asset_source::PATH_LIMIT + std::mem::size_of::<Self>())
    }
}

struct HistoryRegistration {
    root: RegisteredRoot,
}
/// Produced only by this Host's actual PRE/exclusion/POST startup; the caller
/// must additionally await its original startup task before consuming it.
pub(crate) struct HistoryTicket {
    owner: Arc<()>,
    epoch: u64,
    source_epoch: u64,
    lease: Arc<HistoryLease>,
    work_end: Instant,
    original: Arc<HistoryRegistration>,
}

/// Closed private factoring of the SAME storage/IPC startup. Desktop tickets
/// and their native registration map remain unchanged and cannot be synthesized
/// from the history arm. Neither arm is a public/serialized authority surface.
#[derive(Clone, Copy)]
pub(super) enum StartupRef<'a> {
    Document(&'a AllowTicket),
    History(&'a HistoryTicket),
}
impl<'a> StartupRef<'a> {
    pub(super) fn epoch(self) -> u64 {
        match self {
            Self::Document(v) => v.epoch,
            Self::History(v) => v.epoch,
        }
    }
    pub(super) fn path(self) -> &'a Path {
        match self {
            Self::Document(v) => &v.original.canonical_root,
            Self::History(v) => &v.original.root.path,
        }
    }
    pub(super) fn alias(self) -> &'a str {
        match self {
            Self::Document(v) => &v.original.runtime_id,
            Self::History(_) => ALIAS,
        }
    }
    pub(super) fn identity(self) -> Result<(u64, u64), Error> {
        match self {
            Self::Document(v) => Ok((v.original.device, v.original.inode)),
            Self::History(v) => v
                .original
                .root
                .identity
                .posix()
                .map(|id| id.service_identity())
                .map_err(source_error),
        }
    }
    pub(super) fn deadline(self) -> Instant {
        match self {
            Self::Document(v) => v.startup_expires,
            Self::History(v) => v.work_end,
        }
    }
    pub(super) fn check(self, host: &ApplicationHost, state: &Control) -> Result<(), Error> {
        match self {
            Self::Document(v) => {
                if host.history_lease.is_some() {
                    return Err(Error::AccessDenied);
                }
                host.check_startup(state, v)
            }
            Self::History(v) => host.check_history_ticket(state, v),
        }
    }
    pub(super) fn register(self, state: &mut Control) {
        if let Self::Document(v) = self {
            state
                .registered
                .insert(v.original.runtime_id.clone(), v.original.clone());
        }
    }
}

impl ApplicationHost {
    pub(crate) fn new_history(lease: Arc<HistoryLease>) -> Self {
        let mut host = Self::new();
        host.history_lease = Some(lease);
        host.originals.get_mut().headless_sources = Some(Sources::new());
        host
    }
    pub(crate) fn history_deadline(&self) -> Result<Instant, Error> {
        let lease = self.history_lease.as_ref().ok_or(Error::AccessDenied)?;
        Ok(lease.startup_expires())
    }
    fn history_startup_current(&self) -> Result<(), Error> {
        let lease = self.history_lease.as_ref().ok_or(Error::AccessDenied)?;
        lease.current()?;
        if Instant::now() >= self.history_deadline()? {
            return Err(Error::Expired);
        }
        self.lock()?.available()
    }
    fn check_history_ticket(&self, state: &Control, ticket: &HistoryTicket) -> Result<(), Error> {
        state.available()?;
        if !Arc::ptr_eq(&self.identity, &ticket.owner)
            || !self
                .history_lease
                .as_ref()
                .is_some_and(|lease| Arc::ptr_eq(lease, &ticket.lease))
            || state.pending != Some(ticket.epoch)
            || state.source_epoch != ticket.source_epoch
        {
            return Err(Error::AccessDenied);
        }
        ticket.lease.current()?;
        if Instant::now() >= ticket.work_end {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub(super) fn startup_current_origin(&self, ticket: StartupRef<'_>) -> Result<(), Error> {
        let state = self.lock()?;
        ticket.check(self, &state)?;
        if state.phase != Phase::Starting {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(super) fn history_source_bound(&self, originals: &Originals) -> Result<(), Error> {
        let Some(sources) = &originals.headless_sources else {
            return Ok(());
        };
        let total = sources
            .bytes()
            .and_then(|bytes| match originals.source.as_ref() {
                Some(book) => book
                    .retained_bytes()
                    .and_then(|extra| bytes.checked_add(extra)),
                None => Some(bytes),
            });
        if !total.is_some_and(|bytes| bytes <= SOURCE_CONTROL_BYTES) {
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
    /// This fixed startup is the only caller of the new history origin. The
    /// original foreground retains its JoinHandle and this Host before polling.
    pub(crate) async fn prepare_history(
        &self,
        project: PathBuf,
        app_data: PathBuf,
    ) -> Result<HistoryTicket, Error> {
        if self.history_started.swap(true, Ordering::AcqRel) {
            return Err(Error::AccessDenied);
        }
        let result = self.prepare_history_once(project, app_data).await;
        if let Err(error) = result.as_ref() {
            self.startup_failure(HostFailure::simple(HostStage::Admission, *error));
        }
        result
    }
    async fn prepare_history_once(
        &self,
        project: PathBuf,
        app_data: PathBuf,
    ) -> Result<HistoryTicket, Error> {
        self.history_startup_current()?;
        if !ordinary_absolute(&project)
            || !ordinary_absolute(&app_data)
            || project.as_os_str().len() > asset_source::PATH_LIMIT
            || app_data.as_os_str().len() > asset_source::PATH_LIMIT
        {
            return Err(Error::InvalidRequest);
        }
        let root = {
            let mut originals = self.originals.lock().await;
            self.history_startup_current()?;
            let sources = originals
                .headless_sources
                .as_mut()
                .ok_or(Error::StateUnknown)?;
            if !sources.pre.not_started() {
                return Err(Error::AccessDenied);
            }
            let proof = asset_source::probe_project(&mut sources.pre, project, &[], &mut || {
                self.history_startup_current().is_err()
            })
            .map_err(source_error)?;
            if !sources.pre.settled() {
                return Err(Error::StateUnknown);
            }
            let root = RegisteredRoot {
                path: proof.path().to_owned(),
                identity: proof.identity(),
            };
            sources.proof = Some(proof);
            self.history_source_bound(&originals)?;
            root
        };
        let ticket = {
            let mut state = self.lock()?;
            self.history_lease
                .as_ref()
                .ok_or(Error::AccessDenied)?
                .current()?;
            // Only a genuine completed PRE supplies this roster. The history
            // Host has no Document map and admits only ONE startup ever.
            Self::reserve_location_locked(&mut state, &app_data, std::slice::from_ref(&root))?;
            state.retire_pending()?;
            state.pending = Some(state.epoch);
            HistoryTicket {
                owner: self.identity.clone(),
                epoch: state.epoch,
                source_epoch: state.source_epoch,
                lease: self.history_lease.as_ref().unwrap().clone(),
                work_end: self.history_deadline()?,
                original: Arc::new(HistoryRegistration { root }),
            }
        };
        self.prepare_storage(StartupRef::History(&ticket), &app_data, true)
            .await?;
        {
            let mut originals = self.originals.lock().await;
            self.history_startup_current()?;
            let store = originals.store.as_ref().ok_or(Error::StateUnknown)?;
            let application = held_application_root(store).map_err(|error| {
                self.startup_failure(HostFailure::storage(HostStage::Register, error))
            })?;
            let sources = originals
                .headless_sources
                .as_mut()
                .ok_or(Error::StateUnknown)?;
            let proof = asset_source::probe_project_excluding_private_roots(
                &mut sources.post,
                ticket.original.root.path.clone(),
                &[],
                None,
                Some(&application),
                &mut || self.history_startup_current().is_err(),
            )
            .map_err(source_error)?;
            if proof.path() != ticket.original.root.path.as_path()
                || proof.identity() != ticket.original.root.identity
                || !proof.excludes_application(Some(&application))
            {
                return Err(Error::Conflict);
            }
            sources.post_proof = Some(proof);
            if !sources.settled() {
                return Err(Error::StateUnknown);
            }
            self.history_source_bound(&originals)?;
        }
        self.history_startup_current()?;
        Ok(ticket)
    }
    /// Call ONLY after the foreground awaited the original startup task. Source
    /// POST is an admission observation, not a fresh project snapshot or lease
    /// on arbitrary future project contents. Every cached observation stays stale.
    pub(crate) fn finish_history(&self, ticket: HistoryTicket) -> Result<ReadAccessStatus, Error> {
        let originals = self.originals.try_lock().map_err(|_| Error::Busy)?;
        self.history_source_bound(&originals)?;
        let sources = originals
            .headless_sources
            .as_ref()
            .ok_or(Error::StateUnknown)?;
        if !sources.settled()
            || ![sources.proof.as_ref(), sources.post_proof.as_ref()]
                .into_iter()
                .all(|proof| {
                    proof.is_some_and(|proof| {
                        proof.path() == ticket.original.root.path.as_path()
                            && proof.identity() == ticket.original.root.identity
                    })
                })
            || !originals.source.as_ref().is_some_and(SourceBook::settled)
            || originals.server.is_none()
        {
            return Err(Error::StateUnknown);
        }
        let mut state = self.lock()?;
        self.check_history_ticket(&state, &ticket)?;
        if state.phase != Phase::Listening
            || state.prepared != Some(ticket.epoch)
            || !state.registered.is_empty()
        {
            return Err(Error::Conflict);
        }
        state.pending = None;
        state.prepared = None;
        let binding = state.prepared_binding.take().ok_or(Error::StateUnknown)?;
        let (device, inode) = ticket
            .original
            .root
            .identity
            .posix()
            .map_err(source_error)?
            .service_identity();
        if binding.canonical_root
            != ticket
                .original
                .root
                .path
                .to_str()
                .ok_or(Error::InvalidRequest)?
            || (binding.device, binding.inode) != (device, inode)
        {
            return Err(Error::Conflict);
        }
        let service = originals.service.as_ref().ok_or(Error::StateUnknown)?;
        if !state
            .service
            .as_ref()
            .is_some_and(|same| Arc::ptr_eq(same, service))
        {
            return Err(Error::Conflict);
        }
        let result = service.allow_history_read(binding.project_id, &ticket.lease);
        if let Err(error) = result {
            state.fail(HostFailure::simple(HostStage::Publish, error));
        }
        result
    }
    /// Mark before any potentially blocking cleanup. This does not assert a
    /// source/worker/endpoint close and cannot revive a failed original.
    pub(crate) fn stop_history(&self) {
        if let Some(lease) = &self.history_lease {
            lease.stop();
        }
    }
    pub(crate) fn history_join_failed(&self) {
        self.stop_history();
        self.startup_failure(HostFailure::simple(HostStage::Join, Error::StateUnknown));
    }
}

#[cfg(test)]
#[path = "application_service_headless_tests.rs"]
mod tests;
