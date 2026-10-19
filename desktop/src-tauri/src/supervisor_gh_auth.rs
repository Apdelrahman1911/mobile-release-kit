//! Fixed private gh-auth arm of the EXISTING Supervisor. No new driver,
//! watchdog, process group, command executor, or public output channel.
//! Root's central Profile/Resources/retirement branches call these closed
//! helpers. Until those original owners are installed the route is unavailable.
use super::*;
use crate::{github_auth_capture_wire as wire, github_connection_session::auth_provider};
use zeroize::Zeroizing;

/// Closed DATA allocation followed by the actual Supervisor admission. The
/// gate is minted only by the retained original Document operation; reserving
/// storage neither examines a path nor admits a provider from version text.
pub(crate) struct GitHubAuthAdmission {
    pub(super) invocation: Invocation,
    pub(super) endpoints: Endpoints,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) slots: Arc<Mutex<crate::installed_runtime::GitHubAuthRuntimeSlots>>,
    bytes: usize,
}
pub(super) struct Invocation {
    pub(super) gate: crate::asset_session::GitHubAuthGoGate,
    pub(super) context: wire::Context,
    pub(super) role: wire::Role,
    pub(super) mailbox: Arc<Mutex<Mailbox>>,
    request: Mutex<Option<Arc<wire::Request>>>,
}
impl GitHubAuthAdmission {
    pub(crate) fn reservation_bytes() -> Option<usize> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            crate::installed_runtime::GitHubAuthRuntimeSlots::working_reservation_bytes()?
                .checked_add(
                    std::mem::size_of::<Self>()
                        + std::mem::size_of::<Owner>()
                        + std::mem::size_of::<Resources>()
                        + 256 * 1024,
                )
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            None
        }
    }
    pub(crate) fn reserve(
        gate: crate::asset_session::GitHubAuthGoGate,
        context: wire::Context,
        role: wire::Role,
        original_end: Instant,
    ) -> Result<Self, BridgeError> {
        gate.check_current(&context)?; // Caller is OUTSIDE the Document mutex.
        let endpoints =
            Endpoints::at(Instant::now(), original_end).ok_or_else(BridgeError::timeout)?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let bytes = Self::reservation_bytes().ok_or_else(BridgeError::invalid)?;
            let mut slots = crate::installed_runtime::GitHubAuthRuntimeSlots::new();
            slots
                .reserve_once()
                .map_err(|_| BridgeError::unavailable("The fixed gh-auth storage was refused."))?;
            Ok(Self {
                invocation: Invocation {
                    gate,
                    context,
                    role,
                    mailbox: Arc::new(Mutex::new(Mailbox::new())),
                    request: Mutex::new(None),
                },
                endpoints,
                slots: Arc::new(Mutex::new(slots)),
                bytes,
            })
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = (gate, context, role, endpoints);
            Err(BridgeError::unavailable(
                "The fixed gh-auth runtime is unavailable.",
            ))
        }
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}
impl Invocation {
    pub(super) fn request(&self) -> Result<Arc<wire::Request>, BridgeError> {
        self.request
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn inspect(
        &self,
        runtime: &RuntimeConfig,
        owner: &Owner,
        native: &Arc<Mutex<crate::installed_runtime::GitHubAuthRuntimeSlots>>,
    ) -> Result<VerifiedRuntime, BridgeError> {
        self.gate.check_current(&self.context)?;
        let mut slots = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let stop = owner.stop.subscribe();
        let armed = slots.arm_acl_once(owner.endpoint(), &stop);
        owner.observe_native_failure(slots.first_failure());
        armed.map_err(|_| BridgeError::cleanup_unknown())?;
        let selected = runtime.resolve_github_auth_installed(&mut slots, owner.endpoint(), &stop);
        owner.observe_native_failure(slots.first_failure());
        let selected = selected?;
        drop(slots);
        // Called only in Resources.inspection, registered before its worker.
        // The source set is the SAME set retained by the outer Document.
        let original =
            self.gate
                .source_post(&self.context, self.role, SourcePost::Inspect, &mut || {
                    owner.failed() || *stop.borrow() || Instant::now() >= owner.endpoint()
                })?;
        let clock = owner
            .gh_auth_endpoints
            .ok_or_else(BridgeError::cleanup_unknown)?
            .bridge()?;
        let request = Arc::new(wire::Request::from_original_snapshot(
            &owner.id,
            self.role,
            &self.context,
            &original,
            clock,
        )?);
        {
            let mut slot = self
                .request
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if slot.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *slot = Some(request.clone()); // Retain before calling the original gate.
        }
        self.gate.bind_request(&self.context, &owner.id, request)?;
        Ok(selected)
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn post(
        &self,
        owner: &Owner,
        native: &Arc<Mutex<crate::installed_runtime::GitHubAuthRuntimeSlots>>,
        phase: SourcePost,
    ) -> Result<(), BridgeError> {
        self.gate.check_current(&self.context)?;
        let mut slots = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let runtime = slots
            .capability()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let stop = owner.stop.subscribe();
        let result = runtime.post_original(owner.endpoint(), &stop, &mut |first| {
            owner.observe_native_failure(first)
        });
        owner.observe_native_failure(slots.first_failure());
        result.map_err(|failure| match failure {
            crate::installed_runtime::AdmissionFailure::Unknown => BridgeError::cleanup_unknown(),
            crate::installed_runtime::AdmissionFailure::Deadline => BridgeError::timeout(),
            _ => BridgeError::unavailable("The original gh-auth runtime changed."),
        })?;
        drop(slots);
        self.gate
            .source_post(&self.context, self.role, phase, &mut || {
                owner.failed() || *stop.borrow() || Instant::now() >= owner.endpoint()
            })?;
        Ok(())
    }
}

/// Fixed call positions only. This is not a callback/native operation registry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourcePost {
    Inspect,
    BeforeGo,
    AfterWork,
}

impl Supervisor {
    pub(crate) fn github_auth_profile_available(&self) -> bool {
        github_auth_selected(Profile::GitHubAuth)
            && self.inner.runtime.github_auth_profile_available()
    }
    pub(crate) fn start_github_auth(
        &self,
        admission: GitHubAuthAdmission,
    ) -> Result<GitHubAuthTicket, BridgeError> {
        if !self.github_auth_profile_available() {
            return Err(BridgeError::unavailable(
                "The selected official gh provider is unavailable.",
            ));
        }
        admission
            .invocation
            .gate
            .check_current(&admission.invocation.context)?;
        let mailbox = admission.invocation.mailbox.clone();
        let context = admission.invocation.context.clone();
        let role = admission.invocation.role;
        let owner = self.admit(
            AdmissionRequest::GitHubAuth(admission),
            CompletionTarget::GitHubAuth,
        )?;
        Ok(GitHubAuthTicket::new(owner, mailbox, role, context))
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell",
    feature = "custom-protocol",
    not(feature = "development-runtime"),
    not(feature = "ubuntu-runtime-publisher")
))]
pub(super) fn acquire_original(
    inner: &Inner,
    owner: &Arc<Owner>,
    native: &Arc<Mutex<crate::installed_runtime::GitHubAuthRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    let mut slots = native
        .lock()
        .map_err(|_| AcquisitionError::unsupported("gh-auth custody was lost"))?;
    let runtime = slots.capability().map_err(AcquisitionError::capability)?;
    let stop = owner.stop.subscribe();
    let mut first = None;
    let selected = runtime
        .prepare_once_observed(owner.endpoint(), &stop, &mut |value| {
            first = value;
            owner.observe_native_failure(value);
        })
        .map_err(|failure| {
            AcquisitionError::preparation(failure).with_macos_first_failure(first)
        })?;
    let mut command = Command::new(&selected.python);
    command
        .args(["-I", "-S", "-B"])
        .arg(&selected.bootstrap)
        .arg(&selected.core)
        .current_dir(&selected.cwd)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::runtime::macos_installed_environment(&mut command).map_err(AcquisitionError::from)?;
    let owners = lock(&inner.owners);
    let state = lock(&owner.state);
    if !preflight_claim_clear(
        owners
            .get(&owner.key)
            .is_some_and(|actual| Arc::ptr_eq(actual, owner)),
        owner.profile,
        Profile::GitHubAuth,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *owner.stop.borrow(),
    ) {
        return Err(AcquisitionError::unsupported(
            "The original gh-auth claim was refused",
        ));
    }
    runtime
        .claim_once()
        .map_err(AcquisitionError::final_claim)?;
    drop(state);
    drop(owners);
    // The only child is the fixed protected Python bootstrap. Its unchanged
    // C/A/W owns gh AND its nested keyring helper, not this direct-child wait.
    command.spawn().map_err(AcquisitionError::returned_spawn)
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(all(
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    ))
))]
pub(super) fn acquire_original(
    _inner: &Inner,
    _owner: &Arc<Owner>,
    _native: &Arc<Mutex<crate::installed_runtime::GitHubAuthRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    Err(AcquisitionError::unsupported(
        "The fixed gh-auth runtime is unavailable",
    ))
}

#[derive(Clone, Copy)]
pub(crate) struct Endpoints {
    pub(crate) work: Instant,
    pub(crate) hard: Instant,
}
impl Endpoints {
    pub(crate) fn at(start: Instant, original_end: Instant) -> Option<Self> {
        let work = start.checked_add(Duration::from_secs(wire::WORK_SECONDS))?;
        let hard = start.checked_add(Duration::from_secs(wire::HARD_SECONDS))?;
        // Do not create a renewed cleanup window or let per-call timing exceed
        // the original whole selected-account invocation/credential deadline.
        (hard <= original_end).then_some(Self { work, hard })
    }
    pub(crate) fn first_failure(self, at: Instant) -> Instant {
        at.min(self.work)
            .checked_add(Duration::from_secs(10))
            .unwrap_or(self.hard)
            .min(self.hard)
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn bridge(self) -> Result<wire::Clock, BridgeError> {
        let mut original = mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let clock = wire::Clock {
            work_end_ns: original
                .endpoint(self.work)
                .ok_or_else(BridgeError::cleanup_unknown)?,
            hard_end_ns: original
                .endpoint(self.hard)
                .ok_or_else(BridgeError::cleanup_unknown)?,
        };
        if !clock.valid() {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(clock)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitHubAuthReceipt {
    Pending,
    RetainedUnknown,
    Settled,
    Consumed,
}

/// Raw bytes never inhabit ReadEnd.bytes/ReadOutcome/BridgeError/serde/events.
/// Mailbox methods are visible only inside the original Supervisor module.
pub(super) struct Mailbox {
    state: GitHubAuthReceipt,
    raw: Option<Zeroizing<Vec<u8>>>,
    stderr_bytes: Option<usize>,
    terminal: Option<wire::Terminal>,
    failure: Option<BridgeError>,
    read_returned: bool,
    decoded: bool,
}
impl Mailbox {
    pub(super) fn new() -> Self {
        Self {
            state: GitHubAuthReceipt::Pending,
            raw: None,
            stderr_bytes: None,
            terminal: None,
            failure: None,
            read_returned: false,
            decoded: false,
        }
    }
    fn stdout_returned(&mut self, raw: Zeroizing<Vec<u8>>) -> Result<(), BridgeError> {
        if self.state != GitHubAuthReceipt::Pending
            || self.read_returned
            || self.raw.is_some()
            || self.decoded
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.read_returned = true;
        self.raw = Some(raw);
        Ok(())
    }
    fn stderr_returned(&mut self, count: usize) -> Result<(), BridgeError> {
        if self.state != GitHubAuthReceipt::Pending || self.stderr_bytes.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        self.stderr_bytes = Some(count);
        Ok(())
    }
    // Only drive calls this AFTER original child wait AND original IO joins,
    // BEFORE any native code/source close. Unknown/malformed/missing is debt.
    pub(super) fn decode_before_native_close(
        &mut self,
        request: &wire::Request,
    ) -> Result<(), BridgeError> {
        if self.state != GitHubAuthReceipt::Pending
            || self.decoded
            || !self.read_returned
            || self.stderr_bytes != Some(0)
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.decoded = true;
        self.terminal = Some(request.terminal(self.raw.take().ok_or_else(BridgeError::protocol)?)?);
        Ok(())
    }
    pub(super) fn unknown(&mut self) {
        if self.state == GitHubAuthReceipt::Consumed {
            return;
        }
        self.state = GitHubAuthReceipt::RetainedUnknown;
        self.raw = None;
        self.terminal = None; // Zeroizing drop, no successful retry.
        self.failure = Some(BridgeError::cleanup_unknown());
    }
    // Called ONLY by Owner.retire after its actual driver/watchdog/native/IO
    // originals have joined. A decoded terminal never calls this itself.
    pub(super) fn retire(&mut self, outcome: Result<(), BridgeError>, was_unknown: bool) {
        if was_unknown || self.state == GitHubAuthReceipt::RetainedUnknown {
            self.unknown();
            return;
        }
        if self.state != GitHubAuthReceipt::Pending {
            self.unknown();
            return;
        }
        if let Err(error) = outcome {
            self.terminal = None;
            self.raw = None;
            self.failure = Some(error);
        } else if !self.decoded || self.terminal.is_none() || self.stderr_bytes != Some(0) {
            self.unknown();
            return;
        }
        self.state = GitHubAuthReceipt::Settled;
    }
    fn consume(&mut self) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        if self.state != GitHubAuthReceipt::Settled {
            return Err(BridgeError::cleanup_unknown());
        }
        self.state = GitHubAuthReceipt::Consumed; // Retire before any fallible take/parse.
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.terminal
            .take()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .result()
    }
}

/// Original ticket, not Clone/serde. A separate wait handle carries no secret
/// or consume authority and is awaited OUTSIDE the DocumentBinding mutex.
pub(crate) struct GitHubAuthTicket {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    observer: Arc<FinalObserverReturn>,
    role: wire::Role,
    context: wire::Context,
}
pub(crate) struct GitHubAuthWait {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    observer: Arc<FinalObserverReturn>,
}

// The Supervisor's existing retirement already joins every required native
// and management operation. This fixed caller additionally joins its exact
// final observer tail before a second 128MiB runtime reservation or token
// consumption. It adds NO task, executor, process owner, or public proof DTO.
// The actual handle remains in Owner.observer until a positive returned join.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ObserverReturn {
    Fresh,
    Entered,
    Returned,
    Unknown,
}
pub(super) struct FinalObserverReturn {
    state: Mutex<ObserverReturn>,
}
impl FinalObserverReturn {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(ObserverReturn::Fresh),
        }
    }
    fn receipt(&self, result: GitHubAuthReceipt) -> GitHubAuthReceipt {
        match self.state.lock() {
            Ok(state) => match (*state, result) {
                (ObserverReturn::Unknown, _) => GitHubAuthReceipt::RetainedUnknown,
                (ObserverReturn::Returned, value) => value,
                (_, GitHubAuthReceipt::Settled) => GitHubAuthReceipt::Pending,
                (_, value) => value,
            },
            Err(_) => GitHubAuthReceipt::RetainedUnknown,
        }
    }
    pub(super) async fn join_original(&self, owner: &Owner) -> bool {
        {
            let Ok(mut state) = self.state.lock() else {
                return false;
            };
            if *state == ObserverReturn::Returned {
                return true;
            }
            if *state != ObserverReturn::Fresh {
                return false;
            }
            *state = ObserverReturn::Entered; // Retire the sole join route BEFORE await.
        }
        let mut guard = ObserverReturnGuard {
            original: self,
            owner,
            returned: false,
        };
        let endpoint = {
            let state = lock(&owner.state);
            if !state.terminal || state.unknown {
                return false;
            }
            state.cleanup_endpoint.unwrap_or(state.endpoint)
        };
        if Instant::now() >= endpoint {
            return false;
        }
        let deadline = tokio::time::Instant::from_std(endpoint);
        let mut slot = tokio::select! {
            slot = owner.observer.lock() => slot,
            _ = tokio::time::sleep_until(deadline) => return false,
        };
        let Some(handle) = slot.as_mut() else {
            return false;
        };
        let joined = tokio::select! {
            result = handle => result.is_ok(),
            _ = tokio::time::sleep_until(deadline) => false,
        };
        // A consumed failed/late handle remains retained and is never repolled.
        if !joined || Instant::now() >= endpoint {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if *state != ObserverReturn::Entered {
            return false;
        }
        slot.take();
        *state = ObserverReturn::Returned;
        guard.returned = true;
        true
    }
}
struct ObserverReturnGuard<'a> {
    original: &'a FinalObserverReturn,
    owner: &'a Owner,
    returned: bool,
}
impl Drop for ObserverReturnGuard<'_> {
    fn drop(&mut self) {
        if !self.returned {
            *self
                .original
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = ObserverReturn::Unknown;
        }
        self.owner.changed.notify_waiters();
    }
}
impl GitHubAuthTicket {
    pub(super) fn new(
        owner: Arc<Owner>,
        mailbox: Arc<Mutex<Mailbox>>,
        role: wire::Role,
        context: wire::Context,
    ) -> Self {
        Self {
            owner,
            mailbox,
            observer: Arc::new(FinalObserverReturn::new()),
            role,
            context,
        }
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn role(&self) -> wire::Role {
        self.role
    }
    pub(crate) fn context(&self) -> &wire::Context {
        &self.context
    }
    pub(crate) fn wait_handle(&self) -> GitHubAuthWait {
        GitHubAuthWait {
            owner: self.owner.clone(),
            mailbox: self.mailbox.clone(),
            observer: self.observer.clone(),
        }
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The selected GitHub CLI read was stopped.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubAuthReceipt {
        self.observer.receipt(receipt(&self.owner, &self.mailbox))
    }
    pub(crate) fn consume(self) -> Result<Zeroizing<Vec<u8>>, auth_provider::Failure> {
        // Full same-original current source/consent checking belongs to the
        // containing native CaptureOwner, immediately before this private take.
        let original = lock(&self.owner.state);
        if !original.terminal
            || original.unknown
            || self.observer.receipt(GitHubAuthReceipt::Settled) != GitHubAuthReceipt::Settled
        {
            return Err(auth_provider::Failure::Unknown);
        }
        self.mailbox
            .lock()
            .map_err(|_| auth_provider::Failure::Unknown)?
            .consume()
            .map_err(|error| match error.code.as_str() {
                "cancelled" | "gh_auth_refused" => auth_provider::Failure::Refused,
                "query_timeout" => auth_provider::Failure::TimedOut,
                "cleanup_unknown" => auth_provider::Failure::Unknown,
                _ => auth_provider::Failure::InvalidOutput,
            })
    }
}
fn receipt(owner: &Owner, mailbox: &Mutex<Mailbox>) -> GitHubAuthReceipt {
    let original = lock(&owner.state);
    if original.unknown {
        return GitHubAuthReceipt::RetainedUnknown;
    }
    match mailbox.lock() {
        Ok(value) if original.terminal => value.state,
        Ok(value) if value.state == GitHubAuthReceipt::Pending => GitHubAuthReceipt::Pending,
        _ => GitHubAuthReceipt::RetainedUnknown,
    }
}
impl GitHubAuthWait {
    pub(crate) fn receipt(&self) -> GitHubAuthReceipt {
        self.observer.receipt(receipt(&self.owner, &self.mailbox))
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The selected GitHub CLI read was stopped.",
        ));
    }
    pub(crate) async fn returned(&self) -> GitHubAuthReceipt {
        loop {
            // Register before sampling to avoid a completion notification race.
            let changed = self.owner.changed.notified();
            let state = receipt(&self.owner, &self.mailbox);
            if state == GitHubAuthReceipt::Settled {
                if self.observer.join_original(&self.owner).await {
                    return self.receipt();
                }
                lock(&self.mailbox).unknown();
                return GitHubAuthReceipt::RetainedUnknown;
            }
            if state != GitHubAuthReceipt::Pending {
                return self.observer.receipt(state);
            }
            changed.await;
        }
    }
}

/// Nonsecret observer of the EXISTING HTTP owner's original joins. The
/// ConnectionState keeps the actual ticket and result; no HTTP bytes or token
/// are copied here, and this handle cannot accept a /user result by itself.
pub(crate) struct GitHubAuthHttpWait {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubReadReceipt>>,
    observer: FinalObserverReturn,
}
impl GitHubReadTicket {
    pub(crate) fn gh_auth_wait(&self) -> GitHubAuthHttpWait {
        GitHubAuthHttpWait {
            owner: self.owner.clone(),
            receipt: self.receipt.clone(),
            observer: FinalObserverReturn::new(),
        }
    }
}
impl GitHubAuthHttpWait {
    pub(crate) fn receipt(&self) -> GitHubAuthReceipt {
        self.observer.receipt(self.owner_receipt())
    }
    fn owner_receipt(&self) -> GitHubAuthReceipt {
        let original = lock(&self.owner.state);
        if original.unknown {
            return GitHubAuthReceipt::RetainedUnknown;
        }
        match &*lock(&self.receipt) {
            GitHubReadReceipt::RetainedUnknown
            | GitHubReadReceipt::Settled {
                was_unknown: true, ..
            } => GitHubAuthReceipt::RetainedUnknown,
            GitHubReadReceipt::Settled { .. } if original.terminal => GitHubAuthReceipt::Settled,
            _ => GitHubAuthReceipt::Pending,
        }
    }
    pub(crate) async fn returned(&self) -> GitHubAuthReceipt {
        loop {
            let changed = self.owner.changed.notified();
            let result = self.owner_receipt();
            if result == GitHubAuthReceipt::Settled {
                return if self.observer.join_original(&self.owner).await {
                    self.receipt()
                } else {
                    GitHubAuthReceipt::RetainedUnknown
                };
            }
            if result != GitHubAuthReceipt::Pending {
                return self.observer.receipt(result);
            }
            changed.await;
        }
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The selected-account identity read was stopped.",
        ));
    }
}

pub(super) async fn post_after_work(
    resources: &mut Resources,
    inner: &Inner,
    owner: &Arc<Owner>,
) -> bool {
    if resources.gh_auth_after.is_some()
        || resources.gh_auth_after_return.is_some()
        || resources.gh_auth_after_failed
    {
        owner.unknown(inner);
        return false;
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let native = resources.github_auth.clone();
        let original = owner.clone();
        let (start, enter) = oneshot::channel();
        resources.gh_auth_after = Some(tokio::task::spawn_blocking(move || {
            let result = (|| {
                enter
                    .blocking_recv()
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let native = native.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
                original
                    .gh_auth
                    .as_ref()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .post(&original, native, SourcePost::AfterWork)
            })();
            if let Err(error) = &result {
                original.fail(error.clone());
            }
            result
        }));
        if start.send(()).is_err() {
            owner.fail(BridgeError::cleanup_unknown());
        }
        match join_slot(&mut resources.gh_auth_after).await {
            Ok(result) => {
                resources.gh_auth_after.take();
                let unknown = result
                    .as_ref()
                    .is_err_and(|error| error.code == "cleanup_unknown");
                resources.gh_auth_after_return = Some(result);
                if unknown {
                    owner.unknown(inner);
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                resources.gh_auth_after_failed = true;
                owner.unknown(inner);
                false
            }
        }
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        owner.unknown(inner);
        false
    }
}

/// Both stdout and stderr start in Zeroizing storage, including the read
/// scratch. Existing passive read_bounded's Vec is intentionally NOT reused.
/// The returned ReadEnd contains only EOF/overflow facts and an EMPTY Vec.
pub(super) async fn read_private<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    stdout: bool,
    request: Arc<wire::Request>,
    mailbox: Arc<Mutex<Mailbox>>,
    ready: Option<oneshot::Sender<Result<(), BridgeError>>>,
    faults: mpsc::Sender<BridgeError>,
) -> ReadEnd {
    let mut ready = ready;
    let expected = request.ready();
    let mut buffer = Zeroizing::new([0u8; 4096]);
    let mut raw = Zeroizing::new(Vec::new());
    let mut header = !stdout;
    let mut count = 0usize;
    let mut overflow = false;
    let mut eof = false;
    if raw.try_reserve_exact(wire::RESPONSE_LIMIT).is_err() {
        let _ = faults.try_send(BridgeError::cleanup_unknown());
        return ReadEnd {
            bytes: Vec::new(),
            eof,
            overflow: true,
        };
    }
    loop {
        let read = match reader.read(&mut buffer[..]).await {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(used) => used,
            Err(_) => {
                let _ = faults.try_send(BridgeError::new(
                    "io_error",
                    "The private gh-auth channel failed.",
                ));
                break;
            }
        };
        count = count.saturating_add(read);
        if count > wire::RESPONSE_LIMIT {
            if !overflow {
                let _ = faults.try_send(BridgeError::new(
                    "output_limit",
                    "The private gh-auth output exceeded its bound.",
                ));
            }
            overflow = true;
            continue; // Drain only this original pipe to EOF.
        }
        if stdout {
            raw.extend_from_slice(&buffer[..read]);
            if !header {
                let compared = raw.len().min(expected.len());
                if raw[..compared] != expected[..compared] || raw.len() > expected.len() {
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(Err(BridgeError::protocol()));
                    }
                    let _ = faults.try_send(BridgeError::protocol());
                    overflow = true;
                } else if raw.len() == expected.len() {
                    header = true;
                    raw.clear(); // Only known nonsecret READY bytes.
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(Ok(()));
                    }
                }
            }
        }
    }
    if let Some(ready) = ready {
        let _ = ready.send(Err(BridgeError::protocol()));
    }
    if eof && !overflow && header {
        let result = mailbox
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())
            .and_then(|mut value| {
                if stdout {
                    value.stdout_returned(raw)
                } else {
                    value.stderr_returned(count)
                }
            });
        if let Err(error) = result {
            let _ = faults.try_send(error);
        }
    }
    ReadEnd {
        bytes: Vec::new(),
        eof,
        overflow,
    }
}

// The driver receives and joins the source POST using its actual retained
// Resources, not a callback that could reacquire its async mutex and deadlock.
pub(super) async fn write_private(
    mut writer: tokio::process::ChildStdin,
    request: Arc<wire::Request>,
    context: wire::Context,
    gate: crate::asset_session::GitHubAuthGoGate,
    ready: oneshot::Receiver<Result<(), BridgeError>>,
    wait_returned: oneshot::Receiver<()>,
    post_request: oneshot::Sender<oneshot::Sender<Result<(), BridgeError>>>,
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    faults: mpsc::Sender<BridgeError>,
) -> WriteEnd {
    let mut stop = owner.stop.subscribe();
    if *stop.borrow() || owner.failed() || Instant::now() >= owner.endpoint() {
        return WriteEnd { complete: false };
    }
    let result = tokio::select! { biased; _ = stop.changed() => return WriteEnd { complete: false }, value = writer.write_all(request.raw()) => value };
    if result.is_err() {
        owner.fail(BridgeError::new(
            "io_error",
            "The private gh-auth request channel failed.",
        ));
        return WriteEnd { complete: false };
    }
    let ready = tokio::select! { biased; _ = stop.changed() => return WriteEnd { complete: false }, value = ready => value };
    if !matches!(ready, Ok(Ok(()))) {
        owner.fail(BridgeError::protocol());
        return WriteEnd { complete: false };
    }
    let (reply, returned) = oneshot::channel();
    if post_request.send(reply).is_err() {
        owner.fail(BridgeError::cleanup_unknown());
        return WriteEnd { complete: false };
    }
    let posted = tokio::select! { biased; _ = stop.changed() => return WriteEnd { complete: false }, value = returned => value };
    if !matches!(posted, Ok(Ok(()))) {
        owner.fail(BridgeError::cleanup_unknown());
        return WriteEnd { complete: false };
    }
    let go = gate.claim(
        &owner.id,
        &request.digest(),
        &context,
        request.role(),
        || claim_preflight_go(&inner, &owner, Profile::GitHubAuth),
    );
    let go = match go {
        Ok(go) if go == request.go() => go,
        _ => {
            owner.fail(BridgeError::cleanup_unknown());
            return WriteEnd { complete: false };
        }
    };
    if *stop.borrow() || owner.failed() || Instant::now() >= owner.endpoint() {
        return WriteEnd { complete: false };
    }
    let written = tokio::select! { biased; _ = stop.changed() => return WriteEnd { complete: false }, value = writer.write_all(&go) => value };
    if written.is_err() {
        owner.fail(BridgeError::new(
            "io_error",
            "The private gh-auth GO channel failed.",
        ));
        return WriteEnd { complete: false };
    }
    // Keep the parent pipe held through the child's C/A/W/handler/source cleanup.
    // Gh waiting/EOF alone is never a nested-helper finality signal.
    let waited = tokio::select! { biased; _ = stop.changed() => false, value = wait_returned => value.is_ok() };
    let closed = writer.shutdown().await.is_ok();
    if !closed {
        let _ = faults.try_send(BridgeError::cleanup_unknown());
    }
    drop(writer);
    WriteEnd {
        complete: waited && closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn final_observer_missing_or_entered_is_not_a_consumable_original() {
        // Owner terminal here is DATA only. No native driver/source evidence is
        // manufactured; absent original handle must still refuse consumption.
        let owner = super::super::tests::inert_owner();
        lock(&owner.state).terminal = true;
        let tail = FinalObserverReturn::new();
        assert_eq!(
            tail.receipt(GitHubAuthReceipt::Settled),
            GitHubAuthReceipt::Pending
        );
        assert!(!tail.join_original(&owner).await);
        assert_eq!(
            tail.receipt(GitHubAuthReceipt::Settled),
            GitHubAuthReceipt::RetainedUnknown
        );
        assert!(!tail.join_original(&owner).await);
        let entered = FinalObserverReturn {
            state: Mutex::new(ObserverReturn::Entered),
        };
        assert!(!entered.join_original(&owner).await);
    }
    #[tokio::test]
    async fn fixed_observer_tail_joins_the_same_stored_task_once_not_native_qualification() {
        let owner = super::super::tests::inert_owner();
        lock(&owner.state).terminal = true; // Bookkeeping fixture, not OS proof.
        *owner.observer.lock().await = Some(tokio::spawn(async {}));
        let tail = FinalObserverReturn::new();
        assert_eq!(
            tail.receipt(GitHubAuthReceipt::Settled),
            GitHubAuthReceipt::Pending
        );
        assert!(tail.join_original(&owner).await);
        assert!(owner.observer.try_lock().unwrap().is_none());
        assert_eq!(
            tail.receipt(GitHubAuthReceipt::Settled),
            GitHubAuthReceipt::Settled
        );
        assert!(tail.join_original(&owner).await); // Saved ACTUAL join, no repoll.
        assert_eq!(
            tail.receipt(GitHubAuthReceipt::RetainedUnknown),
            GitHubAuthReceipt::RetainedUnknown
        );
    }
    fn request() -> Arc<wire::Request> {
        let snapshot = |mode: u32| wire::Snapshot {
            identity: (1, 2, 0o100000 | mode, 1001, 1001, 1, 12, 123, 456),
            sha256: "a".repeat(64),
        };
        Arc::new(
            wire::Request::from_original_snapshot(
                "gh-auth-fixture",
                wire::Role::Token,
                &wire::Context {
                    login: "fixture-login".into(),
                    project_id: "fixture-project".into(),
                    repository: "fixture-owner/fixture-repo".into(),
                    generation: 1,
                    revision: "fixture-revision".into(),
                },
                &wire::Native {
                    uid: 1001,
                    gid: 1001,
                    home: "/fixture/home".into(),
                    config: "/fixture/home/.config/gh".into(),
                    executable: "/fixture/official/gh".into(),
                    tool: snapshot(0o755),
                    files: wire::Files {
                        config: snapshot(0o600),
                        hosts: snapshot(0o600),
                    },
                },
                wire::Clock {
                    work_end_ns: 40_000_000_000,
                    hard_end_ns: 50_000_000_000,
                },
            )
            .unwrap(),
        )
    }
    fn terminal(request: &wire::Request, status: u8, output: &[u8]) -> Zeroizing<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut raw = Zeroizing::new(b"MRK-GH-AUTH/1\0".to_vec());
        raw.extend_from_slice(&Sha256::digest(request.raw()));
        raw.push(status);
        raw.extend_from_slice(&(output.len() as u16).to_be_bytes());
        raw.extend_from_slice(output);
        raw
    }
    #[tokio::test]
    async fn actual_memory_pipe_reader_keeps_raw_output_out_of_public_read_end() {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(16384);
        let (ready, ready_read) = oneshot::channel();
        let (faults, mut fault_read) = mpsc::channel(4);
        let task = tokio::spawn(read_private(
            reader,
            true,
            request.clone(),
            mailbox.clone(),
            Some(ready),
            faults.clone(),
        ));
        writer.write_all(&request.ready()).await.unwrap();
        ready_read.await.unwrap().unwrap();
        writer
            .write_all(&terminal(
                &request,
                0,
                b"synthetic-private-output-not-a-credential\n",
            ))
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let read = task.await.unwrap();
        assert!(read.eof && !read.overflow && read.bytes.is_empty());
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.shutdown().await.unwrap();
        let stderr = read_private(
            reader,
            false,
            request.clone(),
            mailbox.clone(),
            None,
            faults,
        )
        .await;
        assert!(stderr.eof && !stderr.overflow && stderr.bytes.is_empty());
        assert!(fault_read.try_recv().is_err());
        // Mailbox DATA checks only: this test does NOT construct a ticket or
        // native Owner/retirement. Real native finality is never manufactured.
        let mut value = mailbox.lock().unwrap();
        assert!(value.consume().is_err());
        value.decode_before_native_close(&request).unwrap();
        assert!(value.consume().is_err());
        value.retire(Ok(()), false);
        assert_eq!(
            value.consume().unwrap().as_slice(),
            b"synthetic-private-output-not-a-credential\n"
        );
        assert!(value.consume().is_err());
    }
    #[tokio::test]
    async fn stderr_is_private_even_on_refusal_and_cannot_authorize_success() {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer
            .write_all(b"synthetic-private-stderr-not-a-credential")
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let (faults, _) = mpsc::channel(4);
        let read = read_private(
            reader,
            false,
            request.clone(),
            mailbox.clone(),
            None,
            faults,
        )
        .await;
        assert!(read.eof && !read.overflow && read.bytes.is_empty());
        let mut value = mailbox.lock().unwrap();
        assert!(value.stderr_bytes.is_some_and(|n| n > 0));
        assert!(value.decode_before_native_close(&request).is_err());
        value.retire(Ok(()), false);
        assert_eq!(value.state, GitHubAuthReceipt::RetainedUnknown);
    }
    #[tokio::test]
    async fn unsolicited_private_terminal_before_go_is_not_a_ready_success() {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(16384);
        // One already buffered read, before any parent READY acknowledgement.
        writer.write_all(&request.ready()).await.unwrap();
        writer
            .write_all(&terminal(&request, 0, b"synthetic"))
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let (ready, read_ready) = oneshot::channel();
        let (faults, _) = mpsc::channel(4);
        let read = read_private(
            reader,
            true,
            request.clone(),
            mailbox.clone(),
            Some(ready),
            faults,
        )
        .await;
        assert!(read.eof && read.overflow && read.bytes.is_empty());
        assert!(read_ready.await.unwrap().is_err());
        assert!(mailbox
            .lock()
            .unwrap()
            .decode_before_native_close(&request)
            .is_err());
    }
    #[tokio::test]
    async fn output_limit_still_drains_only_original_memory_pipe_and_returns_no_raw_bytes() {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(16384);
        writer
            .write_all(&vec![b'x'; wire::RESPONSE_LIMIT + 1])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let (faults, _) = mpsc::channel(4);
        let read = read_private(reader, false, request, mailbox.clone(), None, faults).await;
        assert!(read.eof && read.overflow && read.bytes.is_empty());
        assert!(mailbox.lock().unwrap().stderr_bytes.is_none());
    }
    #[test]
    fn original_deadline_cannot_be_renewed_per_capture() {
        let start = Instant::now();
        assert!(Endpoints::at(start, start + Duration::from_secs(29)).is_none());
        let end = Endpoints::at(start, start + Duration::from_secs(60)).unwrap();
        assert_eq!(end.work, start + Duration::from_secs(20));
        assert_eq!(end.hard, start + Duration::from_secs(30));
        assert_eq!(
            end.first_failure(start + Duration::from_secs(2)),
            start + Duration::from_secs(12)
        );
        assert_eq!(end.first_failure(end.hard), end.hard);
    }
    #[test]
    fn missing_terminal_or_unknown_never_mints_a_consumable_private_capture() {
        let mut value = Mailbox::new();
        assert!(value.consume().is_err());
        value.retire(Ok(()), false);
        assert_eq!(value.state, GitHubAuthReceipt::RetainedUnknown);
        value.retire(Ok(()), false);
        assert!(value.consume().is_err());
        let mut value = Mailbox::new();
        value.retire(Err(BridgeError::protocol()), false);
        assert!(value.consume().is_err());
        assert_eq!(value.state, GitHubAuthReceipt::Consumed);
        assert!(value.consume().is_err());
    }
}
