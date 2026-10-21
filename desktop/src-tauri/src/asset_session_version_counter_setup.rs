//! Read-only native-state facet of the SAME admitted publication Owner.
//! No second clock/receipt, protected Authority, namespace, write or agent grant.
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use crate::version_allocation_state_native::counter_setup::Proof as CounterStateProof;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{
    application_service_host::{NativeProject, NativeStateReady, NativeStateTicket},
    version_allocation_state_native::counter_setup::{Custody, SNAPSHOT_WORK},
};
use crate::{
    github_connection_session::publication::refused,
    github_publication_protocol::{
        self as p,
        counter::{CounterTarget, InitialVersion, Purpose, VersionSource},
    },
    supervisor::{PublicationControl, VersionAllocationSourceInput},
};
use std::path::PathBuf;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) enum CounterStateProof {}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl CounterStateProof {
    pub(crate) fn project_id(&self) -> &str {
        match *self {}
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        match *self {}
    }
}

// Charged inside the existing publication 8MiB retained partition, not added
// to it. Includes three <=1MiB original Store snapshots, prior reviewed bytes,
// bounded parser/copies, ready/Host cells and all three fixed job handles.
const QUOTE: usize = 6 * 1024 * 1024;
fn changed() -> BridgeError {
    refused(p::Reason::CounterStateChanged)
}
fn unavailable() -> BridgeError {
    refused(p::Reason::CounterStateUnavailable)
}
fn held<T>(slot: &Mutex<T>) -> Result<MutexGuard<'_, T>, BridgeError> {
    slot.lock().map_err(|_| BridgeError::cleanup_unknown())
}

pub(super) struct Facet {
    document: Weak<Inner>,
    saved: Arc<SavedObservationLane>,
    input: Arc<VersionAllocationSourceInput>,
    generation: u32,
    stamp: crate::edit_owner::SavedEditStamp,
    input_epoch: u64,
    app_data: PathBuf,
    version: InitialVersion,
    ledger_id: String,
    previous: Option<Arc<CounterStateProof>>,
    target: Option<CounterTarget>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    native: Mutex<Native>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    prepare_job: tokio::sync::Mutex<Option<Job>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    read_job: tokio::sync::Mutex<Option<Job>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    retire_job: tokio::sync::Mutex<Option<Job>>,
}
impl Facet {
    /// Pure original saved-input capture under Doc/Edit, before Owner admission.
    pub(super) fn new(
        document: &DocumentBinding,
        state: &DocumentState,
        project: &str,
        generation: u32,
        reference: &str,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        app_data: Option<PathBuf>,
        ledger_id: String,
        previous: Option<Arc<CounterStateProof>>,
    ) -> Result<Arc<Self>, BridgeError> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (
                document, state, project, generation, reference, edit, app_data, ledger_id,
                previous,
            );
            return Err(unavailable());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let binding = state
                .saved_input
                .as_ref()
                .ok_or_else(|| refused(p::Reason::SavedInputsRequired))?;
            let (saved, input) = binding
                .version_source_input(&document.inner, project, reference, edit)
                .map_err(|_| refused(p::Reason::SavedInputsRequired))?;
            let version = binding
                .counter_initial_version()
                .map_err(|_| refused(p::Reason::CounterVersionUnsupported))?;
            let app_data = app_data
                .filter(|v| v.is_absolute())
                .ok_or_else(unavailable)?;
            let stamp = edit.stamp()?;
            let input_epoch = saved.tool_source_epoch();
            Ok(Arc::new(Self {
                document: Arc::downgrade(&document.inner),
                saved,
                input,
                generation,
                stamp,
                input_epoch,
                app_data,
                version,
                ledger_id,
                previous,
                target: None,
                native: Mutex::new(Native::default()),
                prepare_job: tokio::sync::Mutex::new(None),
                read_job: tokio::sync::Mutex::new(None),
                retire_job: tokio::sync::Mutex::new(None),
            }))
        }
    }
    /// Bind actual selected Connection IDs before the sole Owner is admitted.
    /// Arc::get_mut on the gate guarantees this cannot retarget a live facet.
    pub(super) fn bind(&mut self, old: p::Target) -> Result<p::Selection, BridgeError> {
        if self.target.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        let target = CounterTarget {
            purpose: Purpose::Counter,
            project_binding: old.project_binding,
            repository: old.repository,
            account_id: old.account_id,
            repository_id: old.repository_id,
            base: old.base,
            marker: old.marker,
            project_id: self.previous.as_ref().map(|v| v.project_id().to_owned()),
            ledger_id: self.ledger_id.clone(),
            initial_version: self.version.clone(),
            saved_config: p::Fingerprint {
                bytes: self.input.configuration_size,
                sha256: self.input.configuration_sha256.clone(),
            },
            saved_version: VersionSource {
                path: self.input.version_path.clone(),
                bytes: self.input.version_size,
                sha256: self.input.version_sha256.clone(),
            },
        };
        if !target.valid() {
            return Err(refused(p::Reason::InvalidInput));
        }
        self.target = Some(target.clone());
        Ok(p::Selection::Counter(target))
    }
    pub(super) fn quote(&self) -> Option<usize> {
        QUOTE
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(self.app_data.capacity())?
            .checked_add(self.input.root.path.capacity())?
            .checked_add(self.input.project_id.capacity())?
            .checked_add(self.input.reference.capacity())?
            .checked_add(self.input.version_path.capacity())?
            .checked_add(self.input.configuration_sha256.capacity())?
            .checked_add(self.input.version_sha256.capacity())?
            .checked_add(self.version.name.capacity())?
            .checked_add(self.ledger_id.capacity())?
            .checked_add(self.target.as_ref().map_or(Some(0), |t| t.heap())?)?
            .checked_add(self.previous.as_ref().map_or(Some(0), |p| p.heap())?)
    }
    pub(super) fn current_locked(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> bool {
        self.document
            .upgrade()
            .is_some_and(|v| Arc::ptr_eq(&v, &document.inner))
            && !state.retiring
            && !state.stopping
            && !state.quit_pending
            && !state.unknown
            && edit.matches(&self.stamp)
            && document.inner.bridge.registry_generation() == self.generation
            && state.saved_input.as_ref().is_some_and(|v| {
                v.matches_version_source(&document.inner, &self.saved, &self.input, edit)
            })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn current(&self) -> Result<(DocumentBinding, NativeProject), BridgeError> {
        let document = DocumentBinding {
            inner: self.document.upgrade().ok_or_else(changed)?,
        };
        let state = document.lock();
        let edit = document
            .inner
            .bridge
            .edits
            .saved_registration_guard(&document.inner.session_identity)?;
        if !self.current_locked(&document, &state, &edit) {
            return Err(changed());
        }
        let (generation, root) = document
            .inner
            .bridge
            .native_project(&self.input.project_id)
            .map_err(|_| changed())?;
        if generation != self.generation || root != self.input.root {
            return Err(changed());
        }
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| changed())?
            .service_identity();
        let native = NativeProject {
            runtime_id: self.input.project_id.clone(),
            canonical_root: root.path,
            device,
            inode,
            registration_generation: generation,
            document_identity: document.inner.session_identity.clone(),
            input_revision: self.input_epoch,
        };
        drop(edit);
        drop(state);
        Ok((document, native))
    }
    pub(super) fn project_before_go(&self) -> Option<String> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let native = held(&self.native).ok()?;
            let custody = held(native.custody.as_ref()?).ok()?;
            custody.proof_before_go().map(|p| p.project_id().to_owned())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }
    pub(super) fn retired_proof(&self) -> Option<Arc<CounterStateProof>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let native = held(&self.native).ok()?;
            if !native.settled {
                return None;
            }
            let custody = held(native.custody.as_ref()?).ok()?;
            custody.retired_proof()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }
    pub(super) fn settled(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            held(&self.native).is_ok_and(|v| v.settled)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }
    pub(super) async fn prepare(
        self: &Arc<Self>,
        control: PublicationControl,
    ) -> Result<(), BridgeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut slot = self.prepare_job.lock().await;
            if slot.is_some() || !control.current() {
                return Err(BridgeError::cleanup_unknown());
            }
            let (send, receive) = tokio::sync::oneshot::channel();
            *slot = Some(Job::new(send));
            let original = self.clone();
            let job_control = control.clone();
            slot.as_mut().unwrap().handle = Some(tokio::spawn(async move {
                let result = async {
                    receive.await.map_err(|_| changed())?;
                    if !job_control.current() {
                        return Err(changed());
                    }
                    original.prepare_original(&job_control).await
                }
                .await;
                fail_return(&job_control, &result);
                result
            }));
            // Handle and whole facet are retained BEFORE the Host can enter.
            let current = self.current().map(|_| ());
            if let Err(error) = current {
                control.fail_at(error.clone(), Instant::now());
                slot.as_mut().unwrap().release.take();
            } else if control.current() {
                slot.as_mut()
                    .unwrap()
                    .release
                    .take()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .send(())
                    .map_err(|_| BridgeError::cleanup_unknown())?;
            } else {
                slot.as_mut().unwrap().release.take();
            }
            join(slot.as_mut().unwrap(), &control).await?;
            slot.as_ref().unwrap().outcome()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = control;
            Err(unavailable())
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn prepare_original(
        self: &Arc<Self>,
        control: &PublicationControl,
    ) -> Result<(), BridgeError> {
        let (document, native) = self.current()?;
        let host = &document.inner.bridge.application_service;
        let end = control
            .work_end()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        {
            let state = document.lock();
            let edit = document
                .inner
                .bridge
                .edits
                .saved_registration_guard(&document.inner.session_identity)?;
            if !self.current_locked(&document, &state, &edit) || !control.current() {
                return Err(changed());
            }
            let roster = document
                .inner
                .bridge
                .native_roster()
                .map_err(|_| changed())?;
            host.reserve_native_state_location(&self.app_data, &roster.roots)
                .map_err(host_error)?;
            let ticket = host
                .begin_native_state_until(native, end)
                .map_err(host_error)?;
            held(&self.native)?.host_ticket = Some(Arc::new(ticket));
        }
        let ticket = held(&self.native)?
            .host_ticket
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone();
        // The outer retained Job observes THIS future, including every Host IO
        // and its own original source/process retirement, before GO can run.
        let prepared = host.prepare_native_state(&ticket, &self.app_data).await;
        held(&self.native)?.host_returned = true;
        prepared.map_err(host_error)?;
        let (_, current) = self.current()?;
        if !control.current() {
            return Err(changed());
        }
        held(&self.native)?.finish_attempted = true;
        let ready = match host.finish_native_state_retained(&ticket, &current) {
            Ok(v) => Arc::new(v),
            Err(_) => return Err(BridgeError::cleanup_unknown()), // pending may already be consumed; never retry/cancel it
        };
        held(&self.native)?.ready = Some(ready.clone());
        let actual = ready
            .retained_bytes()
            .and_then(|v| v.checked_add(SNAPSHOT_WORK))
            .and_then(|v| v.checked_add(64 * 1024));
        if !actual.is_some_and(|v| v <= QUOTE) {
            return Err(refused(p::Reason::ResourcesUnavailable));
        }
        let target = self
            .target
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let custody = Arc::new(Mutex::new(Custody::new(
            ready.clone(),
            target.repository_id.clone(),
            self.previous.clone(),
        )));
        held(&self.native)?.custody = Some(custody.clone());
        let mut slot = self.read_job.lock().await;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        let (send, receive) = tokio::sync::oneshot::channel();
        *slot = Some(Job::new(send));
        let job_control = control.clone();
        slot.as_mut().unwrap().handle = Some(tokio::task::spawn_blocking(move || {
            let result = (|| {
                receive.blocking_recv().map_err(|_| changed())?;
                if !job_control.current() {
                    return Err(changed());
                }
                let mut held = held(&custody)?;
                if !job_control.current() {
                    return Err(changed());
                }
                held.load()?;
                if !job_control.current() {
                    return Err(changed());
                }
                held.recheck()
            })();
            fail_return(&job_control, &result);
            result
        }));
        let rematch = (|| {
            let (_, native) = self.current()?;
            host.native_state_current(&ready, &native)
                .map_err(host_error)?;
            let state = document.lock();
            let edit = document
                .inner
                .bridge
                .edits
                .saved_registration_guard(&document.inner.session_identity)?;
            if !self.current_locked(&document, &state, &edit) || !control.current() {
                return Err(changed());
            }
            slot.as_mut()
                .unwrap()
                .release
                .take()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .send(())
                .map_err(|_| BridgeError::cleanup_unknown())
        })();
        if let Err(error) = rematch {
            control.fail_at(error, Instant::now());
            slot.as_mut().unwrap().release.take();
        }
        join(slot.as_mut().unwrap(), control).await?;
        slot.as_ref().unwrap().outcome()?;
        let (_, native) = self.current()?;
        host.native_state_current(&ready, &native)
            .map_err(host_error)?;
        if !control.current() {
            return Err(changed());
        }
        Ok(())
    }
    /// Called only after SAME Owner's driver and watchdog/management originals
    /// returned, before its terminal receipt. No wait on our own final receipt.
    pub(super) async fn finalize(self: &Arc<Self>, control: PublicationControl) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let result = self.finish_original(&control).await;
            if result.is_err() {
                control.unknown();
            }
            result.is_ok()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = control;
            false
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn finish_original(&self, control: &PublicationControl) -> Result<(), BridgeError> {
        if !control.management_returned() || !control.cleanup_current() {
            return Err(BridgeError::cleanup_unknown());
        }
        let mut prepare = self.prepare_job.lock().await;
        if let Some(job) = prepare.as_mut() {
            if !job.returned() {
                join(job, control).await?;
            }
        }
        let mut read = self.read_job.lock().await;
        if let Some(job) = read.as_mut() {
            if !job.returned() {
                join(job, control).await?;
            }
        }
        if prepare.as_ref().is_some_and(|j| !j.returned())
            || read.as_ref().is_some_and(|j| !j.returned())
        {
            return Err(BridgeError::cleanup_unknown());
        }
        drop(read);
        drop(prepare);
        let document = self
            .document
            .upgrade()
            .map(|inner| DocumentBinding { inner })
            .ok_or_else(BridgeError::cleanup_unknown)?;
        // A failed currentness check is an original failure, not a reason to
        // skip consuming closure or replace the failed snapshot with new DATA.
        if let Err(error) = self.current() {
            control.fail_at(error, Instant::now());
        }
        let (ticket, custody, finish_attempted, ready, host_returned) = {
            let v = held(&self.native)?;
            if v.settled {
                return Err(BridgeError::cleanup_unknown());
            }
            (
                v.host_ticket.clone(),
                v.custody.clone(),
                v.finish_attempted,
                v.ready.is_some(),
                v.host_returned,
            )
        };
        if let Some(ticket) = ticket {
            if !host_returned {
                return Err(BridgeError::cleanup_unknown());
            }
            if finish_attempted && !ready {
                return Err(BridgeError::cleanup_unknown());
            }
            if !finish_attempted {
                if !control.cleanup_current() {
                    return Err(BridgeError::cleanup_unknown());
                }
                document
                    .inner
                    .bridge
                    .application_service
                    .cancel_native_state_ticket(&ticket)
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                held(&self.native)?.host_cancelled = true;
            }
        }
        if let Some(custody) = custody {
            let mut slot = self.retire_job.lock().await;
            if slot.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            let (send, receive) = tokio::sync::oneshot::channel();
            *slot = Some(Job::new(send));
            let job_control = control.clone();
            slot.as_mut().unwrap().handle = Some(tokio::task::spawn_blocking(move || {
                let result = (|| {
                    receive
                        .blocking_recv()
                        .map_err(|_| BridgeError::cleanup_unknown())?;
                    if !job_control.management_returned() || !job_control.cleanup_current() {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    let mut held = held(&custody)?;
                    if !job_control.cleanup_current() {
                        return Err(BridgeError::cleanup_unknown());
                    }
                    held.retire()
                })();
                fail_return(&job_control, &result);
                result
            }));
            if !control.cleanup_current() {
                slot.as_mut().unwrap().release.take();
                return Err(BridgeError::cleanup_unknown());
            }
            slot.as_mut()
                .unwrap()
                .release
                .take()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .send(())
                .map_err(|_| BridgeError::cleanup_unknown())?;
            join(slot.as_mut().unwrap(), control).await?;
            // A known post-read refusal may have positively retired NativeUse.
            // It keeps the original failure and withholds proof, not closure.
            if slot.as_ref().unwrap().outcome().is_err()
                && !held(
                    held(&self.native)?
                        .custody
                        .as_ref()
                        .ok_or_else(BridgeError::cleanup_unknown)?,
                )?
                .retired()
            {
                return Err(BridgeError::cleanup_unknown());
            }
        }
        if !control.cleanup_current() {
            return Err(BridgeError::cleanup_unknown());
        }
        held(&self.native)?.settled = true;
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct Native {
    host_ticket: Option<Arc<NativeStateTicket>>,
    host_returned: bool,
    finish_attempted: bool,
    ready: Option<Arc<NativeStateReady>>,
    custody: Option<Arc<Mutex<Custody>>>,
    host_cancelled: bool,
    settled: bool,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Job {
    release: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<Result<(), BridgeError>>>,
    result: Option<Result<(), BridgeError>>,
    join_error: Option<tokio::task::JoinError>,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Job {
    fn new(release: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            release: Some(release),
            handle: None,
            result: None,
            join_error: None,
        }
    }
    fn returned(&self) -> bool {
        self.handle.is_none() && self.result.is_some() && self.join_error.is_none()
    }
    fn outcome(&self) -> Result<(), BridgeError> {
        self.result
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone()
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fail_return(control: &PublicationControl, result: &Result<(), BridgeError>) {
    if let Err(error) = result {
        let at = Instant::now();
        control.fail_at(error.clone(), at);
        if error.code == "cleanup_unknown" {
            control.unknown();
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn join(job: &mut Job, control: &PublicationControl) -> Result<(), BridgeError> {
    if job.returned() {
        return Ok(());
    }
    let mut stop = control
        .stop_clock()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let (returned, end) = loop {
        let end = control
            .cleanup_end()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        tokio::select! {biased;
            returned=job.handle.as_mut().ok_or_else(BridgeError::cleanup_unknown)?=>break(returned,end),
            changed=stop.changed()=>{if changed.is_err(){control.unknown();return Err(BridgeError::cleanup_unknown());}},
            _=tokio::time::sleep_until(end.into())=>{control.unknown();return Err(BridgeError::cleanup_unknown());},
        }
    };
    match returned {
        Ok(result) => {
            job.result = Some(result);
            job.handle.take();
        }
        Err(error) => {
            job.join_error = Some(error);
            control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
    }
    if Instant::now() >= end || !control.cleanup_current() {
        control.unknown();
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn host_error(error: crate::service_protocol::Error) -> BridgeError {
    use crate::service_protocol::Error;
    match error {
        Error::StateUnknown => BridgeError::cleanup_unknown(),
        Error::Busy => refused(p::Reason::Busy),
        Error::Expired | Error::AccessDenied => refused(p::Reason::Expired),
        Error::Conflict => changed(),
        _ => unavailable(),
    }
}
