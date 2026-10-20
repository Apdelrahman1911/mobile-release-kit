//! Consume-once reservation on the ORIGINAL ReleaseVersion EditOwner.
//!
//! The old Reserve SourceBook has CLOSED. Its snapshot is comparison DATA.
//! This Session owns a distinct GitReadSources in its existing inspection,
//! acquisition and consuming-close jobs. No second executor or lock owner.
use super::*;
use crate::{asset_session::ReservedVersionEditGate, supervisor::VersionReserveControl};
use std::sync::{OnceLock, Weak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservedVersionStep {
    Open,
    Opened,
    Prepare,
    Prepared,
    Apply,
    Terminal,
    Retired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Bound,
    Opening,
    Editing,
    Preparing,
    Reviewing,
    Applying,
    Finalizing,
    Returned,
}
fn successor(stage: Stage, step: ReservedVersionStep) -> Option<Stage> {
    use ReservedVersionStep as S;
    Some(match (stage, step) {
        (Stage::Bound, S::Open) => Stage::Opening,
        (Stage::Opening, S::Opened) => Stage::Editing,
        (Stage::Editing, S::Prepare) => Stage::Preparing,
        (Stage::Preparing, S::Prepared) => Stage::Reviewing,
        (Stage::Reviewing, S::Apply) => Stage::Applying,
        (Stage::Applying, S::Terminal) => Stage::Finalizing,
        (Stage::Finalizing, S::Retired) => Stage::Returned,
        _ => return None,
    })
}
struct Chain {
    epoch: u64,
    stage: Stage,
    pending: Option<(u64, u64, ReservedVersionStep)>,
    failed: bool,
}
impl Chain {
    fn begin(
        &mut self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        let usable = !self.failed
            && self.pending.is_none()
            && !publisher.accepted()
            && successor(self.stage, step).is_some();
        self.failed = true;
        if !usable || publisher.tool_source_epoch()? != self.epoch {
            return Err(invalid_owner());
        }
        self.pending = Some((self.epoch, publisher.reserved_version_serial()?, step));
        self.failed = false;
        Ok(())
    }
    fn accepted(
        &mut self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        let usable = !self.failed && publisher.accepted();
        self.failed = true;
        let expected = self.epoch.checked_add(1).ok_or_else(edit_unknown)?;
        if !usable
            || self.pending != Some((self.epoch, publisher.reserved_version_serial()?, step))
            || publisher.tool_source_epoch()? != expected
        {
            return Err(invalid_owner());
        }
        self.stage = successor(self.stage, step).ok_or_else(invalid_owner)?;
        self.epoch = expected;
        self.pending = None;
        self.failed = false;
        Ok(())
    }
}

/// Not Clone/Serialize. The sole value moves from registered ticket to Session.
/// Only DocumentBinding can supply its original gate; renderer DATA cannot.
pub(crate) struct NativeReservedVersionHandoff {
    gate: ReservedVersionEditGate,
    control: Arc<VersionReserveControl>,
    registration: RegisteredEditRoot,
    data: Value,
    chain: Mutex<Chain>,
    session: OnceLock<Weak<Session>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    sources: Mutex<crate::asset_source::GitReadSources>,
}
impl NativeReservedVersionHandoff {
    pub(crate) fn new(
        gate: ReservedVersionEditGate,
        control: Arc<VersionReserveControl>,
        registration: RegisteredEditRoot,
        data: Value,
        epoch: u64,
    ) -> Result<Self, BridgeError> {
        if !control.edit_window()
            || data["schemaVersion"] != 1
            || data["provider"]["kind"] != "macos-clt-git/1"
            || !((data["reservation"]["request"]["platforms"] == json!(["ios"])
                  && data["reservation"]["request"]["policy"]["schemaVersion"] == 2)
                 || (data["reservation"]["request"]["platforms"] == json!(["android"])
                  && data["reservation"]["request"]["policy"]["schemaVersion"] == 3))
            || wire::bounded(&data, 12 * 1024).is_err()
        {
            return Err(invalid_owner());
        }
        Ok(Self {
            gate,
            control,
            registration,
            data,
            chain: Mutex::new(Chain {
                epoch,
                stage: Stage::Bound,
                pending: None,
                failed: false,
            }),
            session: OnceLock::new(),
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            sources: Mutex::new(crate::asset_source::GitReadSources::new()),
        })
    }
    pub(crate) fn backing_bytes() -> Option<usize> {
        let bytes = std::mem::size_of::<Self>().checked_add(6 * 12 * 1024 + 8192)?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        return bytes.checked_add(crate::asset_source::GitReadSources::working_bytes()?);
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        Some(bytes)
    }
    pub(crate) fn gate(&self) -> &ReservedVersionEditGate {
        &self.gate
    }
    fn chain(&self) -> Result<MutexGuard<'_, Chain>, BridgeError> {
        self.chain.lock().map_err(|_| {
            self.control.unknown();
            edit_unknown()
        })
    }
    pub(crate) fn begin(
        &self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        if !(if step == ReservedVersionStep::Retired {
            self.control.edit_retirement_window()
        } else {
            self.control.edit_window()
        }) || !self.gate.same_publisher(publisher)
        {
            return Err(invalid_owner());
        }
        self.chain()?.begin(publisher, step)
    }
    pub(crate) fn accepted(
        &self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        if !(if step == ReservedVersionStep::Retired {
            self.control.edit_retirement_window()
        } else {
            self.control.edit_window()
        }) || !self.gate.same_publisher(publisher)
        {
            self.fail(false, Instant::now());
            return Err(invalid_owner());
        }
        self.chain()?.accepted(publisher, step)
    }
    pub(crate) fn matches_publisher(&self, publisher: &RegistrationPublisher) -> bool {
        self.gate.same_publisher(publisher)
            && self.chain().is_ok_and(|c| {
                !c.failed
                    && c.pending.is_none()
                    && publisher.accepted()
                    && publisher.tool_source_epoch().is_ok_and(|e| e == c.epoch)
            })
    }
    pub(crate) fn epoch_ready(
        &self,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<bool, BridgeError> {
        let c = self.chain()?;
        if c.failed || c.pending.is_some() {
            return Err(invalid_owner());
        }
        let epoch = match publisher {
            Some(p) if self.gate.same_publisher(p) => p.reserved_version_epoch()?,
            Some(_) => return Err(invalid_owner()),
            None => match self.gate.epoch() {
                Ok(e) => Some(e),
                Err(e) if e.code == "busy" => None,
                Err(e) => return Err(e),
            },
        };
        match epoch {
            Some(e) if e == c.epoch => Ok(true),
            None => Ok(false),
            _ => Err(invalid_owner()),
        }
    }
    pub(crate) fn permits_observation(
        &self,
        original: &crate::saved_command_owner::StoreVersionObservation,
    ) -> bool {
        self.gate.same_observation(original)
            && self.chain().is_ok_and(|c| {
                !c.failed
                    && c.pending.is_none()
                    && !matches!(c.stage, Stage::Bound | Stage::Returned)
                    && if c.stage == Stage::Finalizing {
                        self.control.edit_retirement_window()
                    } else {
                        self.control.edit_window()
                    }
            })
    }
    pub(crate) fn check_document(
        &self,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        self.gate.current(self, publisher)
    }
    /// A pending ordinary publisher is a bounded WAIT, never an epoch rebase.
    /// Callers keep the original writer/STOP endpoint while waiting.
    pub(super) fn ready(&self) -> Result<bool, BridgeError> {
        if !self.control.edit_window() {
            return Err(invalid_owner());
        }
        if self.chain()?.stage == Stage::Returned {
            return Err(invalid_owner());
        }
        self.epoch_ready(None)
    }
    pub(super) fn fail(&self, unknown: bool, at: Instant) {
        match self.chain.lock() {
            Ok(mut c) => c.failed = true,
            Err(e) => {
                e.into_inner().failed = true;
                self.control.unknown();
            }
        }
        if unknown {
            self.control.unknown();
        } else {
            self.control.stop_at(at);
        }
        if let Some(owner) = self.session.get().and_then(Weak::upgrade) {
            owner.stop.send_replace(true);
            owner.wake.notify_waiters();
            if unknown {
                owner.resource_unknown.store(true, Ordering::SeqCst);
            }
        }
    }
    pub(super) fn bind(&self, owner: &Arc<Session>) -> Result<(), BridgeError> {
        if owner.domain != EditDomain::ReleaseVersion
            || owner.saved_text_recovery
            || owner.registration.as_ref() != Some(&self.registration)
            || self.session.set(Arc::downgrade(owner)).is_err()
        {
            return Err(invalid_owner());
        }
        Ok(())
    }
    fn same_session(&self, owner: &Session) -> bool {
        self.session
            .get()
            .is_some_and(|s| std::ptr::eq(s.as_ptr(), owner))
    }
    fn opened(&self, checkout: &version_wire::Opened) -> bool {
        let Ok(baseline) = serde_json::to_value(&checkout.baseline) else {
            return false;
        };
        checkout.ios_enabled
            && self.data["source"]["savedVersion"]["source"].as_str()
                == Some(checkout.source.as_str())
            && baseline["savedConfig"]["sha256"] == self.data["source"]["savedConfig"]["sha256"]
            && baseline["savedVersion"]["sha256"] == self.data["source"]["savedVersion"]["sha256"]
    }
    pub(super) fn values(&self, values: &version_wire::Values) -> bool {
        self.data["reservation"]["version"]["name"].as_str() == Some(values.name.as_str())
            && values.build
                == self.data["reservation"]["version"]["build"]
                    .as_u64()
                    .unwrap_or(u64::MAX)
                    .to_string()
    }
    pub(super) fn publication(
        &self,
        publication: &mut EditPublication<'_>,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        if let Some(p) = publication.owned.as_mut() {
            self.begin(p, step)?;
            // The same original publisher does the actual invalidation.
            if let Err(error) =
                p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)
            {
                self.fail(true, Instant::now());
                return Err(error);
            }
            self.accepted(p, step)
        } else if let Some(p) = publication.borrowed {
            if !self.matches_publisher(p) {
                return Err(invalid_owner());
            }
            let wanted = match step {
                ReservedVersionStep::Open => Stage::Opening,
                ReservedVersionStep::Prepare => Stage::Preparing,
                ReservedVersionStep::Apply => Stage::Applying,
                _ => return Err(invalid_owner()),
            };
            if self.chain()?.stage != wanted {
                return Err(invalid_owner());
            }
            Ok(())
        } else {
            Err(invalid_owner())
        }
    }
    pub(super) fn cleanup_end(&self, end: Instant) -> Instant {
        end.min(self.control.cleanup_end())
    }
    pub(super) fn work_end(&self) -> Instant {
        self.control.work_end()
    }
    pub(super) fn open_data(
        &self,
        publication: &mut EditPublication<'_>,
    ) -> Result<Value, BridgeError> {
        self.publication(publication, ReservedVersionStep::Open)?;
        Ok(self.data.clone())
    }
    fn wait_native(
        &self,
        owner: &Session,
        publisher: Option<&RegistrationPublisher>,
        document: bool,
    ) -> Result<(), BridgeError> {
        loop {
            if *owner.stop.borrow() || !self.control.edit_window() {
                return Err(invalid_owner());
            }
            if self.epoch_ready(publisher)? {
                if !document {
                    return Ok(());
                }
                match self.check_document(publisher) {
                    Ok(()) => return Ok(()),
                    Err(e) if e.code == "busy" => {}
                    Err(e) => return Err(e),
                }
            }
            // SAME existing blocking native job, no handle/clock replacement.
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Stack-only borrow of the actual retained Session. Never reconstructed from
/// a public status; no clone of the consume-once handoff, token or permission.
pub(crate) struct ReservedVersionEditAccess {
    original: Arc<Session>,
}
impl ReservedVersionEditAccess {
    pub(crate) fn handoff(&self) -> &NativeReservedVersionHandoff {
        self.original
            .reserved_version
            .as_ref()
            .expect("retained reserved Session")
    }
    pub(crate) fn begin(
        &self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        self.handoff().begin(publisher, step)
    }
    pub(crate) fn accepted(
        &self,
        publisher: &RegistrationPublisher,
        step: ReservedVersionStep,
    ) -> Result<(), BridgeError> {
        self.handoff().accepted(publisher, step)
    }
    pub(crate) fn current(
        &self,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        self.handoff().check_document(publisher)
    }
    pub(crate) fn failed(&self) {
        self.handoff().fail(false, Instant::now());
    }
}
impl EditOwner {
    /// Same original exact Apply receipt, before any new publisher or chain
    /// transition. This cannot enqueue, retry a write or change finality.
    pub(crate) fn reserved_version_apply_observation(
        &self,
        window: &str,
        session_id: &str,
        plan_token: &str,
    ) -> Result<Option<version_wire::ReleaseVersionEditStatus>, BridgeError> {
        if !wire::token(session_id) || !wire::token(plan_token) {
            return Err(BridgeError::invalid());
        }
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) || r.document_lost {
            return Err(invalid_owner());
        }
        let Some(a) = r.active.as_ref().filter(|a| {
            a.session.id == session_id
                && a.session.domain == EditDomain::ReleaseVersion
                && a.session.reserved_version.is_some()
        }) else {
            return Ok(None);
        };
        if !exact_apply_receipt(
            &a.projection,
            EditDomain::ReleaseVersion,
            &r.generation,
            session_id,
            plan_token,
        ) {
            return Ok(None);
        }
        self.inner.release_version_snapshot(&r).map(Some)
    }
    pub(crate) fn reserved_version_access(
        &self,
        window: &str,
        id: &str,
    ) -> Result<Option<ReservedVersionEditAccess>, BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window)
            || r.document_lost
            || r.disabled
            || r.exhausted
            || self.inner.poisoned.load(Ordering::SeqCst)
        {
            return Err(invalid_owner());
        }
        let Some(a) = r
            .active
            .as_ref()
            .filter(|a| a.session.id == id && a.session.domain == EditDomain::ReleaseVersion)
        else {
            return Ok(None);
        };
        Ok(a.session
            .reserved_version
            .as_ref()
            .map(|_| ReservedVersionEditAccess {
                original: a.session.clone(),
            }))
    }
}
impl RegisteredOpenTicket {
    pub(crate) fn reserved_version(
        &mut self,
        handoff: NativeReservedVersionHandoff,
    ) -> Result<(), BridgeError> {
        if self.domain != EditDomain::ReleaseVersion
            || self.saved_text_recovery
            || self.configuration_recovery
            || self.reserved_version.is_some()
        {
            return Err(invalid_owner());
        }
        self.reserved_version = Some(handoff);
        Ok(())
    }
}

pub(super) fn frame(
    owner: &Session,
    reply: &ChildFrame,
    publication: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(handoff) = &owner.reserved_version else {
        return Ok(());
    };
    if !handoff.same_session(owner) {
        return Err(invalid_owner());
    }
    let step = match reply {
        ChildFrame::ReleaseVersionOpened(checkout) if handoff.opened(checkout) => {
            ReservedVersionStep::Opened
        }
        ChildFrame::ReleaseVersionPrepared(prepared) if handoff.values(&prepared.view.values) => {
            ReservedVersionStep::Prepared
        }
        ChildFrame::ReleaseVersionTerminal(_, terminal)
            if terminal.effect == Effect::Committed
                && terminal.resources == ResourceState::Settled
                && terminal.journal == Journal::Clean =>
        {
            ReservedVersionStep::Terminal
        }
        ChildFrame::ReleaseVersionTerminal(_, _) => {
            handoff.fail(false, Instant::now());
            return Ok(());
        }
        _ => return Err(invalid_owner()),
    };
    handoff.publication(publication, step)
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn source_failure(
    first: Option<(
        mrk_macos_installed_native::vault_filesystem::Failure,
        Instant,
    )>,
) -> Option<(crate::installed_runtime::AdmissionFailure, Instant)> {
    first.map(|(failure, at)| {
        (
            if failure == mrk_macos_installed_native::vault_filesystem::Failure::Unknown {
                crate::installed_runtime::AdmissionFailure::Unknown
            } else {
                crate::installed_runtime::AdmissionFailure::Native
            },
            at,
        )
    })
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn inspect(owner: &Arc<Session>) -> Result<(), BridgeError> {
    let Some(handoff) = &owner.reserved_version else {
        return Ok(());
    };
    handoff.wait_native(owner, None, true)?;
    let mut source = handoff.sources.lock().map_err(|_| {
        handoff.fail(true, Instant::now());
        edit_unknown()
    })?;
    let result = (|| {
        if !source.not_started() {
            return Err(invalid_owner());
        }
        source
            .inspect(
                &handoff.registration.root,
                ReleaseVersionRuntimeSlots::source_runtime_fd_bound(),
                &mut || handoff.wait_native(owner, None, false).is_err(),
            )
            .map_err(|_| invalid_owner())?;
        let native = serde_json::to_value(source.native_snapshot().map_err(|_| invalid_owner())?)
            .map_err(|_| BridgeError::protocol())?;
        if native != handoff.data["provider"]["native"] {
            return Err(invalid_owner());
        }
        Ok(())
    })();
    owner.observe_native_failure(source_failure(source.first_failure()));
    drop(source);
    if result.is_err() {
        handoff.fail(false, Instant::now());
    }
    result?;
    handoff.wait_native(owner, None, true)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn post(
    owner: &Session,
    publisher: Option<&RegistrationPublisher>,
) -> Result<(), BridgeError> {
    let Some(handoff) = &owner.reserved_version else {
        return Ok(());
    };
    handoff.wait_native(owner, publisher, true)?;
    let mut source = handoff.sources.lock().map_err(|_| {
        handoff.fail(true, Instant::now());
        edit_unknown()
    })?;
    let result = source
        .post(&mut || handoff.wait_native(owner, publisher, false).is_err())
        .map_err(|_| invalid_owner());
    owner.observe_native_failure(source_failure(source.first_failure()));
    drop(source);
    if result.is_err() {
        handoff.fail(false, Instant::now());
    }
    result?;
    handoff.wait_native(owner, publisher, true)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn close(owner: &Session, original_end: Instant) -> CloseOutcome {
    let Some(handoff) = &owner.reserved_version else {
        return CloseOutcome::Settled;
    };
    let mut source = match handoff.sources.lock() {
        Ok(s) => s,
        Err(e) => {
            handoff.fail(true, Instant::now());
            let mut s = e.into_inner();
            s.mark_interrupted();
            s
        }
    };
    // No ordinary STOP check here: normal successful terminal closes stdin.
    // Failed post never suppresses the original consuming close attempt.
    let end = handoff.cleanup_end(original_end);
    let post = if source.not_started() {
        true
    } else {
        source.post(&mut || Instant::now() >= end).is_ok()
    };
    owner.observe_native_failure(source_failure(source.first_failure()));
    let close = source
        .close(&mut |first| owner.native_cleanup_expired(end, source_failure(first)))
        .is_ok();
    let settled = close && source.settled();
    drop(source);
    if !post {
        handoff.fail(false, Instant::now());
    }
    if !settled {
        handoff.fail(true, Instant::now());
        CloseOutcome::Unknown
    } else {
        CloseOutcome::Settled
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn settled(owner: &Session) -> bool {
    owner
        .reserved_version
        .as_ref()
        .is_none_or(|h| h.sources.try_lock().is_ok_and(|s| s.settled()))
}

pub(super) async fn wait_command(owner: &Session) -> Result<(), BridgeError> {
    let Some(h) = &owner.reserved_version else {
        return Ok(());
    };
    loop {
        if *owner.stop.borrow() {
            return Err(invalid_owner());
        }
        if h.ready()? {
            return Ok(());
        }
        tokio::select! {_ = owner.wake.notified()=>{},_ = tokio::time::sleep(Duration::from_millis(1))=>{}}
    }
}
pub(super) fn retired(
    owner: &Session,
    publication: &mut EditPublication<'_>,
    current: bool,
) -> bool {
    let Some(h) = &owner.reserved_version else {
        return true;
    };
    if !current || Instant::now() >= h.cleanup_end(Instant::now() + FINALIZATION) {
        h.fail(false, Instant::now());
        return false;
    }
    if h.chain().is_ok_and(|c| c.failed) {
        return false;
    }
    if h.publication(publication, ReservedVersionStep::Retired)
        .is_err()
    {
        h.fail(false, Instant::now());
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saved_command_owner::{
        AndroidRegistrationControl as Control, AndroidRegistrationPublisherKind as Kind,
    };
    fn step(chain: &mut Chain, control: &Arc<Control>, step: ReservedVersionStep) {
        let mut p = control.reserve(Kind::General, false).unwrap();
        chain.begin(&p, step).unwrap();
        p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)
            .unwrap();
        chain.accepted(&p, step).unwrap();
        p.finish();
    }
    #[test]
    fn reserved_version_publications_are_exact_original_phase_successors() {
        let control = Arc::new(Control::default());
        let mut c = Chain {
            epoch: control.epoch().unwrap(),
            stage: Stage::Bound,
            pending: None,
            failed: false,
        };
        for phase in [
            ReservedVersionStep::Open,
            ReservedVersionStep::Opened,
            ReservedVersionStep::Prepare,
            ReservedVersionStep::Prepared,
            ReservedVersionStep::Apply,
            ReservedVersionStep::Terminal,
            ReservedVersionStep::Retired,
        ] {
            step(&mut c, &control, phase);
        }
        assert_eq!(c.stage, Stage::Returned);
        assert_eq!(c.epoch, control.epoch().unwrap());
        let p = control.reserve(Kind::General, false).unwrap();
        assert!(c.begin(&p, ReservedVersionStep::Apply).is_err());
        p.reject();
    }
    #[test]
    fn foreign_or_failed_reserved_publisher_never_rebases_the_chain() {
        let control = Arc::new(Control::default());
        let epoch = control.epoch().unwrap();
        let mut c = Chain {
            epoch,
            stage: Stage::Bound,
            pending: None,
            failed: false,
        };
        let mut p = control.reserve(Kind::General, false).unwrap();
        c.begin(&p, ReservedVersionStep::Open).unwrap();
        p.reject(); // original publication never accepted
        let mut replacement = control.reserve(Kind::General, false).unwrap();
        replacement
            .accept(crate::android_registration_app_protocol::Reason::ContextChanged)
            .unwrap();
        // Equal successor number alone is NOT sufficient: original publisher identity must be retained.
        assert!(c.accepted(&replacement, ReservedVersionStep::Open).is_err());
        replacement.finish();
        let mut d = Chain {
            epoch,
            stage: Stage::Bound,
            pending: None,
            failed: false,
        };
        let foreign = control.reserve(Kind::General, false).unwrap();
        assert!(d.begin(&foreign, ReservedVersionStep::Open).is_err());
        foreign.reject();
    }
}
