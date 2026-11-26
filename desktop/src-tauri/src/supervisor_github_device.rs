//! Closed device exchange arm of the SAME Supervisor driver and native Book. No new driver,
//! watchdog, process group, command executor, or public output channel.
//! Root's central Profile/Resources/retirement branches call these closed
//! helpers. Until those original owners are installed the route is unavailable.
use super::gh_auth::FinalObserverReturn;
pub(crate) use super::gh_auth::GitHubAuthReceipt as GitHubDeviceReceipt;
use super::*;
use crate::github_device_protocol as wire;
use zeroize::Zeroizing;

/// Closed DATA allocation followed by the actual Supervisor admission. The
/// gate is minted only by the retained original Document operation; reserving
/// storage neither examines a path nor admits a provider from version text.
pub(crate) struct GitHubDeviceAdmission {
    pub(super) invocation: Invocation,
    pub(super) endpoints: Endpoints,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) slots: Arc<Mutex<crate::installed_runtime::GitHubDeviceRuntimeSlots>>,
    bytes: usize,
}
pub(super) struct Invocation {
    pub(super) gate: crate::asset_session::GitHubDeviceGoGate,
    pub(super) context: wire::Context,
    pub(super) role: wire::Role,
    pub(super) mailbox: Arc<Mutex<Mailbox>>,
    request: Mutex<Option<Arc<wire::Request>>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    clock: Mutex<Option<mrk_macos_installed_native::vault_helper_wire::ClockBridge>>,
}
impl GitHubDeviceAdmission {
    pub(crate) fn reservation_bytes() -> Option<usize> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            crate::installed_runtime::GitHubDeviceRuntimeSlots::working_reservation_bytes()?
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
        gate: crate::asset_session::GitHubDeviceGoGate,
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
            let mut slots = crate::installed_runtime::GitHubDeviceRuntimeSlots::new();
            slots.reserve_once().map_err(|_| {
                BridgeError::unavailable("The fixed device connection storage was refused.")
            })?;
            Ok(Self {
                invocation: Invocation {
                    gate,
                    context,
                    role,
                    mailbox: Arc::new(Mutex::new(Mailbox::new())),
                    request: Mutex::new(None),
                    clock: Mutex::new(None),
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
                "The fixed device connection runtime is unavailable.",
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
    pub(super) fn decode(&self, owner: &Owner, request: &wire::Request) -> Result<(), BridgeError> {
        let first = {
            let mut mailbox = self
                .mailbox
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            mailbox.decode_before_native_close(request)?;
            mailbox
                .terminal
                .as_ref()
                .ok_or_else(BridgeError::protocol)?
                .first_failure_ns()?
        };
        if let Some(first) = first {
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            {
                let at = self
                    .clock
                    .lock()
                    .map_err(|_| BridgeError::cleanup_unknown())?
                    .as_mut()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .failure_bound(first)
                    .ok_or_else(BridgeError::cleanup_unknown)?;
                owner.fail_at(
                    BridgeError::new("device_refused", "The device exchange was refused."),
                    at,
                );
            }
            #[cfg(not(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )))]
            {
                let _ = (owner, first);
                return Err(BridgeError::cleanup_unknown());
            }
        }
        Ok(())
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
        native: &Arc<Mutex<crate::installed_runtime::GitHubDeviceRuntimeSlots>>,
    ) -> Result<VerifiedRuntime, BridgeError> {
        self.gate.check_current(&self.context)?;
        let mut slots = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let stop = owner.stop.subscribe();
        let armed = slots.arm_acl_once(owner.endpoint(), &stop);
        owner.observe_native_failure(slots.first_failure());
        armed.map_err(|_| BridgeError::cleanup_unknown())?;
        let selected = runtime.resolve_github_device_installed(&mut slots, owner.endpoint(), &stop);
        owner.observe_native_failure(slots.first_failure());
        let selected = selected?;
        drop(slots);
        self.gate
            .post(&self.context, self.role, SourcePost::Inspect)?;
        let endpoints = owner
            .github_device_endpoints
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let bracket = mrk_macos_installed_native::vault_helper_wire::ClockBridge::capture()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let clock = wire::Clock {
            work_end_ns: bracket
                .endpoint(endpoints.work)
                .ok_or_else(BridgeError::cleanup_unknown)?,
            hard_end_ns: bracket
                .endpoint(endpoints.hard)
                .ok_or_else(BridgeError::cleanup_unknown)?,
        };
        let mut slot = self
            .clock
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *slot = Some(bracket);
        drop(slot);
        let request = Arc::new(
            self.gate
                .request(&self.context, &owner.id, self.role, clock)?,
        );
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
        native: &Arc<Mutex<crate::installed_runtime::GitHubDeviceRuntimeSlots>>,
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
            _ => BridgeError::unavailable("The original device connection runtime changed."),
        })?;
        drop(slots);
        self.gate.post(&self.context, self.role, phase)?;
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
    pub(crate) fn github_device_profile_available(&self) -> bool {
        github_device_selected(Profile::GitHubDevice)
            && self.inner.runtime.github_device_profile_available()
    }
    pub(crate) fn start_github_device(
        &self,
        admission: GitHubDeviceAdmission,
    ) -> Result<GitHubDeviceTicket, BridgeError> {
        if !self.github_device_profile_available() {
            return Err(BridgeError::unavailable(
                "The device connection runtime is unavailable.",
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
            AdmissionRequest::GitHubDevice(admission),
            CompletionTarget::GitHubDevice,
        )?;
        Ok(GitHubDeviceTicket::new(owner, mailbox, role, context))
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
    native: &Arc<Mutex<crate::installed_runtime::GitHubDeviceRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    let mut slots = native
        .lock()
        .map_err(|_| AcquisitionError::unsupported("device connection custody was lost"))?;
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
        Profile::GitHubDevice,
        &state,
        Instant::now(),
        inner.stopping.load(Ordering::SeqCst),
        inner.disabled.load(Ordering::SeqCst),
        *owner.stop.borrow(),
    ) {
        return Err(AcquisitionError::unsupported(
            "The original device connection claim was refused",
        ));
    }
    runtime
        .claim_once()
        .map_err(AcquisitionError::final_claim)?;
    drop(state);
    drop(owners);
    // The only child is this fixed protected HTTP bootstrap. The same original
    // driver owns its child, pipes, native runtime and management joins.
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
    _native: &Arc<Mutex<crate::installed_runtime::GitHubDeviceRuntimeSlots>>,
) -> Result<Child, AcquisitionError> {
    Err(AcquisitionError::unsupported(
        "The fixed device connection runtime is unavailable",
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
        // the original whole device invocation/credential deadline.
        (hard <= original_end).then_some(Self { work, hard })
    }
    pub(crate) fn first_failure(self, at: Instant) -> Instant {
        at.min(self.work)
            .checked_add(Duration::from_secs(2))
            .unwrap_or(self.hard)
            .min(self.hard)
    }
}

/// Raw bytes never inhabit ReadEnd.bytes/ReadOutcome/BridgeError/serde/events.
/// Mailbox methods are visible only inside the original Supervisor module.
pub(super) struct Mailbox {
    state: GitHubDeviceReceipt,
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
            state: GitHubDeviceReceipt::Pending,
            raw: None,
            stderr_bytes: None,
            terminal: None,
            failure: None,
            read_returned: false,
            decoded: false,
        }
    }
    fn stdout_returned(&mut self, raw: Zeroizing<Vec<u8>>) -> Result<(), BridgeError> {
        if self.state != GitHubDeviceReceipt::Pending
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
        if self.state != GitHubDeviceReceipt::Pending || self.stderr_bytes.is_some() {
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
        if self.state != GitHubDeviceReceipt::Pending
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
        if self.state == GitHubDeviceReceipt::Consumed {
            return;
        }
        self.state = GitHubDeviceReceipt::RetainedUnknown;
        self.raw = None;
        self.terminal = None; // Zeroizing drop, no successful retry.
        self.failure = Some(BridgeError::cleanup_unknown());
    }
    // Called ONLY by Owner.retire after its actual driver/watchdog/native/IO
    // originals have joined. A decoded terminal never calls this itself.
    pub(super) fn retire(&mut self, outcome: Result<(), BridgeError>, was_unknown: bool) {
        if was_unknown || self.state == GitHubDeviceReceipt::RetainedUnknown {
            self.unknown();
            return;
        }
        if self.state != GitHubDeviceReceipt::Pending {
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
        self.state = GitHubDeviceReceipt::Settled;
    }
    fn consume(&mut self) -> Result<wire::Reply, BridgeError> {
        if self.state != GitHubDeviceReceipt::Settled {
            return Err(BridgeError::cleanup_unknown());
        }
        self.state = GitHubDeviceReceipt::Consumed; // Retire before any fallible take/parse.
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
pub(crate) struct GitHubDeviceTicket {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    observer: Arc<FinalObserverReturn>,
    role: wire::Role,
    context: wire::Context,
}
pub(crate) struct GitHubDeviceWait {
    owner: Arc<Owner>,
    mailbox: Arc<Mutex<Mailbox>>,
    observer: Arc<FinalObserverReturn>,
}

impl GitHubDeviceTicket {
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
    pub(crate) fn wait_handle(&self) -> GitHubDeviceWait {
        GitHubDeviceWait {
            owner: self.owner.clone(),
            mailbox: self.mailbox.clone(),
            observer: self.observer.clone(),
        }
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The device connection was stopped.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubDeviceReceipt {
        self.observer.receipt(receipt(&self.owner, &self.mailbox))
    }
    pub(crate) fn consume(self) -> Result<wire::Reply, BridgeError> {
        let original = lock(&self.owner.state);
        if !original.terminal
            || original.unknown
            || self.observer.receipt(GitHubDeviceReceipt::Settled) != GitHubDeviceReceipt::Settled
        {
            return Err(BridgeError::cleanup_unknown());
        }
        self.mailbox
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .consume()
    }
}
fn receipt(owner: &Owner, mailbox: &Mutex<Mailbox>) -> GitHubDeviceReceipt {
    let original = lock(&owner.state);
    if original.unknown {
        return GitHubDeviceReceipt::RetainedUnknown;
    }
    match mailbox.lock() {
        Ok(value) if original.terminal => value.state,
        Ok(value) if value.state == GitHubDeviceReceipt::Pending => GitHubDeviceReceipt::Pending,
        _ => GitHubDeviceReceipt::RetainedUnknown,
    }
}
impl GitHubDeviceWait {
    pub(crate) fn receipt(&self) -> GitHubDeviceReceipt {
        self.observer.receipt(receipt(&self.owner, &self.mailbox))
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The device connection was stopped.",
        ));
    }
    pub(crate) async fn returned(&self) -> GitHubDeviceReceipt {
        loop {
            // Register before sampling to avoid a completion notification race.
            let changed = self.owner.changed.notified();
            let state = receipt(&self.owner, &self.mailbox);
            if state == GitHubDeviceReceipt::Settled {
                if self.observer.join_original(&self.owner).await {
                    return self.receipt();
                }
                lock(&self.mailbox).unknown();
                return GitHubDeviceReceipt::RetainedUnknown;
            }
            if state != GitHubDeviceReceipt::Pending {
                return self.observer.receipt(state);
            }
            changed.await;
        }
    }
}

pub(super) async fn post_after_work(
    resources: &mut Resources,
    inner: &Inner,
    owner: &Arc<Owner>,
) -> bool {
    if resources.github_device_after.is_some()
        || resources.github_device_after_return.is_some()
        || resources.github_device_after_failed
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
        let native = resources.github_device.clone();
        let original = owner.clone();
        let (start, enter) = oneshot::channel();
        resources.github_device_after = Some(tokio::task::spawn_blocking(move || {
            let result = (|| {
                enter
                    .blocking_recv()
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let native = native.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
                original
                    .github_device
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
        match join_slot(&mut resources.github_device_after).await {
            Ok(result) => {
                resources.github_device_after.take();
                let unknown = result
                    .as_ref()
                    .is_err_and(|error| error.code == "cleanup_unknown");
                resources.github_device_after_return = Some(result);
                if unknown {
                    owner.unknown(inner);
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                resources.github_device_after_failed = true;
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
                    "The private device connection channel failed.",
                ));
                break;
            }
        };
        count = count.saturating_add(read);
        if count > wire::RESPONSE_LIMIT {
            if !overflow {
                let _ = faults.try_send(BridgeError::new(
                    "output_limit",
                    "The private device connection output exceeded its bound.",
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
    gate: crate::asset_session::GitHubDeviceGoGate,
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
            "The private device connection request channel failed.",
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
        || claim_preflight_go(&inner, &owner, Profile::GitHubDevice),
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
            "The private device connection GO channel failed.",
        ));
        return WriteEnd { complete: false };
    }
    // Keep the parent pipe held through the child's C/A/W/handler/source cleanup.
    // A child output frame alone is never native/runtime/management finality.
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
    fn request() -> Arc<wire::Request> {
        Arc::new(
            wire::Request::new(
                "inert-child",
                wire::Role::Poll,
                &wire::Context {
                    operation_id: "inert-device".into(),
                    project_id: "inert-project".into(),
                    repository: "fixture/repository".into(),
                    generation: 1,
                    sequence: 1,
                },
                "inert-client",
                Some("inert-device-code"),
                wire::Clock {
                    work_end_ns: 1,
                    hard_end_ns: 2,
                },
            )
            .unwrap(),
        )
    }
    fn terminal(r: &wire::Request) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(format!("{{\"protocol\":\"{}\",\"id\":\"inert-child\",\"role\":\"poll\",\"requestSha256\":\"{}\",\"status\":\"ok\",\"firstFailureNs\":null,\"reply\":{{\"kind\":\"token\",\"token\":\"inert-not-a-credential\",\"scopes\":[\"repo\"],\"expiresIn\":null}}}}\n",wire::PROTOCOL,r.digest()).into_bytes())
    }
    #[tokio::test]
    async fn original_memory_reader_keeps_private_token_out_of_public_result_until_separate_retirement(
    ) {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(16384);
        let (ready, read_ready) = oneshot::channel();
        let (faults, mut errors) = mpsc::channel(4);
        let task = tokio::spawn(read_private(
            reader,
            true,
            request.clone(),
            mailbox.clone(),
            Some(ready),
            faults.clone(),
        ));
        writer.write_all(&request.ready()).await.unwrap();
        read_ready.await.unwrap().unwrap();
        writer.write_all(&terminal(&request)).await.unwrap();
        writer.shutdown().await.unwrap();
        let result = task.await.unwrap();
        assert!(result.eof && !result.overflow && result.bytes.is_empty());
        let (mut writer, reader) = tokio::io::duplex(16);
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
        assert!(errors.try_recv().is_err());
        // DATA state transitions, not a fake native ticket/receipt. Production
        // retire() belongs ONLY to the existing driver's actual joined tail.
        let mut held = mailbox.lock().unwrap();
        assert!(held.consume().is_err());
        held.decode_before_native_close(&request).unwrap();
        assert!(held.consume().is_err());
        held.retire(Ok(()), false);
        assert!(
            matches!(held.consume(),Ok(wire::Reply::Token{token,..}) if token.as_str()=="inert-not-a-credential")
        );
        assert!(held.consume().is_err());
    }
    #[tokio::test]
    async fn unsolicited_ready_plus_terminal_and_unknown_never_mint_private_reply() {
        let request = request();
        let mailbox = Arc::new(Mutex::new(Mailbox::new()));
        let (mut writer, reader) = tokio::io::duplex(16384);
        writer.write_all(&request.ready()).await.unwrap();
        writer.write_all(&terminal(&request)).await.unwrap();
        writer.shutdown().await.unwrap();
        let (ready, read_ready) = oneshot::channel();
        let (faults, _) = mpsc::channel(4);
        let result = read_private(
            reader,
            true,
            request.clone(),
            mailbox.clone(),
            Some(ready),
            faults,
        )
        .await;
        assert!(result.eof && result.overflow && result.bytes.is_empty());
        assert!(read_ready.await.unwrap().is_err());
        let mut held = mailbox.lock().unwrap();
        assert!(held.decode_before_native_close(&request).is_err());
        held.unknown();
        held.retire(Ok(()), false);
        assert!(held.consume().is_err());
        assert_eq!(held.state, GitHubDeviceReceipt::RetainedUnknown);
    }
    #[test]
    fn per_call_endpoint_and_first_failure_never_extend_original_device_handoff_budget() {
        let start = Instant::now();
        assert!(Endpoints::at(start, start + Duration::from_secs(11)).is_none());
        let e = Endpoints::at(start, start + Duration::from_secs(12)).unwrap();
        assert_eq!(e.work, start + Duration::from_secs(10));
        assert_eq!(e.hard, start + Duration::from_secs(12));
        assert_eq!(
            e.first_failure(start + Duration::from_secs(1)),
            start + Duration::from_secs(3)
        );
        assert_eq!(e.first_failure(start + Duration::from_secs(99)), e.hard);
    }
}
