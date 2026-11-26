//! Session-only device OAuth on the existing auth Entry and OriginalWork.
//! A joined OAuth token is only a private input to the existing fresh HTTP
//! connection. This module never constructs account facts or provider consent.
use super::*;
use crate::{
    github_device_native::Clock,
    github_device_protocol as device,
    supervisor::{
        GitHubDeviceAdmission, GitHubDeviceSourcePost, GitHubDeviceTicket, GitHubDeviceWait,
    },
};
use std::time::SystemTime;
use zeroize::Zeroizing;

fn stale() -> BridgeError {
    BridgeError::new(
        "device_stale",
        "The original device connection context changed.",
    )
}
fn unavailable() -> BridgeError {
    BridgeError::new(
        "device_unconfigured",
        "The publisher has not configured its GitHub OAuth App.",
    )
}
fn stopped() -> BridgeError {
    BridgeError::new(
        "cancelled",
        "The local login was stopped. This does not revoke a GitHub grant.",
    )
}
fn busy() -> BridgeError {
    BridgeError::new("busy", "Finish the original connection first.")
}
fn unknown(error: &BridgeError) -> bool {
    is_unknown(error)
}
fn failure_reason(error: &BridgeError) -> device::Reason {
    match error.code.as_str() {
        "device_denied" => device::Reason::Denied,
        "device_expired" => device::Reason::Expired,
        "device_client_refused" => device::Reason::ClientRefused,
        _ => crate::github_device_native::public_reason(error),
    }
}
fn provider_refusal(reason: device::Reason) -> BridgeError {
    match reason {
        device::Reason::Denied => {
            BridgeError::new("device_denied", "GitHub declined this authorization.")
        }
        device::Reason::Expired => {
            BridgeError::new("device_expired", "The original device code expired.")
        }
        device::Reason::ClientRefused => BridgeError::new(
            "device_client_refused",
            "GitHub refused the configured OAuth application.",
        ),
        _ => BridgeError::protocol(),
    }
}

// Only public bounded historical DATA survives a dropped shell observer.
// At most Start+120 checks can retain one slot each. A slot's actual public
// value is capped at1536; slot/Arc/observer overhead fits the original fixed
// 256KiB Entry reservation. No retired runtime Book is kept by these observers.
const RETURN_DATA_BYTES: usize = 1536;
struct ReplySlot(Mutex<Option<device::Status>>);
impl ReplySlot {
    fn publish(&self, value: device::Status) -> Result<(), BridgeError> {
        if value.retained_bytes().is_none_or(|n| n > RETURN_DATA_BYTES) {
            return Err(BridgeError::cleanup_unknown());
        }
        let mut slot = self.0.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_none() {
            *slot = Some(value)
        }
        Ok(())
    }
    fn take(&self) -> Result<Option<device::Status>, BridgeError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .take())
    }
}
pub(crate) struct Observer {
    document: Weak<Inner>,
    response: Arc<ReplySlot>,
    hard: Instant,
}
impl Observer {
    pub(crate) async fn returned(self) -> Result<device::Status, BridgeError> {
        loop {
            if let Some(value) = self.response.take()? {
                return Ok(value);
            }
            if Instant::now() >= self.hard {
                return Err(BridgeError::cleanup_unknown());
            }
            let Some(inner) = self.document.upgrade() else {
                return Err(BridgeError::cleanup_unknown());
            };
            DocumentBinding { inner }.github_device_status();
            if let Some(value) = self.response.take()? {
                return Ok(value);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Post {
    New,
    Inspected,
    Posted,
    Returned,
}
struct Call {
    role: device::Role,
    sequence: u32,
    admitted: Instant,
    post: Post,
    request: Option<(String, Arc<device::Request>)>,
    go: bool,
}
struct Active {
    ticket: GitHubDeviceTicket,
    wait: Arc<GitHubDeviceWait>,
}
struct Facts {
    phase: device::Phase,
    revision: u32,
    reason: device::Reason,
    clock: Clock,
    failure: Option<BridgeError>,
    unknown: bool,
    command: Option<device::Role>,
    call: Option<Call>,
    dispatch_attempted: bool,
    device_code: Option<Zeroizing<String>>,
    user_code: Option<String>,
    response: Arc<ReplySlot>,
    http_claimed: bool,
    http_started: bool,
    http_settled: bool,
    http: Option<device::Http>,
    body_returned: bool,
    final_join: Option<Instant>,
}
pub(super) struct Registration {
    pub(super) original: Arc<OriginalWork>,
    document: Weak<Inner>,
    session_identity: Arc<()>,
    native_context: Option<Arc<NativeContext>>,
    native_session: bool,
    idle_connection_epoch: u32,
    root: asset_source::RegisteredRoot,
    context: device::Context,
    facts: Mutex<Facts>,
    active: Mutex<Option<Active>>,
    http_wait: Mutex<Option<Arc<GitHubAuthHttpWait>>>,
}
impl Registration {
    pub(super) fn gate(self: &Arc<Self>) -> GitHubDeviceGoGate {
        GitHubDeviceGoGate {
            document: self.document.clone(),
            registration: Arc::downgrade(self),
        }
    }
    fn step(facts: &mut Facts) -> Result<(), BridgeError> {
        facts.revision = facts
            .revision
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or_else(BridgeError::cleanup_unknown)?;
        Ok(())
    }
    // Called from the actual first-F callback. Never recursively calls the same
    // active Supervisor while it holds native slots; Stop separately notifies it.
    fn failure(&self, error: BridgeError, at: Instant) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.clock.fail(at);
            facts.unknown |= unknown(&error);
            if facts.failure.is_none() {
                facts.reason = failure_reason(&error);
                facts.failure = Some(error);
                facts.phase = device::Phase::Stopping;
                let _ = Self::step(&mut facts);
            }
            if facts.unknown {
                facts.phase = device::Phase::CleanupUnknown;
                facts.reason = device::Reason::CleanupUnknown;
            }
            self.original.set_endpoint(facts.clock.cleanup);
        } else {
            self.original.set_endpoint(Some(at));
        }
        self.original.signal_stop();
        self.original.wake.notify_waiters();
    }
    pub(super) fn stop(&self, cause: GitHubReason) {
        self.failure(
            if cause == GitHubReason::Cancelled {
                stopped()
            } else {
                github_session::refused(cause)
            },
            Instant::now(),
        );
        if let Ok(active) = self.active.try_lock() {
            if let Some(active) = &*active {
                active.wait.stop();
            }
        }
        if let Ok(http) = self.http_wait.try_lock() {
            if let Some(http) = &*http {
                http.stop();
            }
        }
    }
    fn error(&self) -> Option<BridgeError> {
        self.facts.lock().map_or_else(
            |_| Some(BridgeError::cleanup_unknown()),
            |f| f.failure.clone(),
        )
    }
    fn bound(&self) -> Instant {
        self.facts.lock().map_or_else(
            |_| Instant::now(),
            |f| f.clock.cleanup.unwrap_or(f.clock.end).min(f.clock.hard),
        )
    }
    fn physically_settled(&self) -> bool {
        let settled = self.original.join_if_ended() == Some(true)
            && self.original.resources_settled()
            && self.active.try_lock().is_ok_and(|a| a.is_none())
            && self.http_wait.try_lock().is_ok_and(|a| a.is_none())
            && self.facts.try_lock().is_ok_and(|f| {
                f.body_returned && !f.dispatch_attempted && (!f.http_started || f.http_settled)
            });
        if settled {
            if let Ok(mut f) = self.facts.try_lock() {
                if f.final_join.is_none() {
                    let now = Instant::now();
                    f.final_join = Some(now);
                    if now >= f.clock.cleanup.unwrap_or(f.clock.end) {
                        f.unknown = true;
                        f.phase = device::Phase::CleanupUnknown;
                        f.reason = device::Reason::CleanupUnknown;
                    }
                }
            } else {
                return false;
            }
        }
        settled
    }
    pub(super) fn custody(&self) -> GitHubAuthCustody {
        let Ok(facts) = self.facts.lock() else {
            return GitHubAuthCustody::Unknown;
        };
        if facts.unknown {
            return GitHubAuthCustody::Unknown;
        }
        drop(facts);
        if !self.physically_settled() {
            return GitHubAuthCustody::Pending;
        }
        let Ok(facts) = self.facts.lock() else {
            return GitHubAuthCustody::Unknown;
        };
        if facts.unknown {
            return GitHubAuthCustody::Unknown;
        }
        if let Some(error) = &facts.failure {
            return GitHubAuthCustody::Refused(match failure_reason(error) {
                device::Reason::Expired => GitHubReason::Expired,
                device::Reason::TargetChanged => GitHubReason::TargetChanged,
                device::Reason::CleanupUnknown => return GitHubAuthCustody::Unknown,
                _ => GitHubReason::Cancelled,
            });
        }
        if facts.http_started && facts.http_settled {
            GitHubAuthCustody::Ready
        } else {
            GitHubAuthCustody::Unknown
        }
    }
    fn snapshot(&self, document: &DocumentBinding, state: &DocumentState) -> device::Status {
        let now = Instant::now();
        let settled = self.physically_settled();
        let Ok(f) = self.facts.lock() else {
            return device::Status {
                schema_version: 1,
                document_revision: state.revision,
                connection_revision: state.github.snapshot().revision,
                available: false,
                operation_id: Some(self.context.operation_id.clone()),
                project_id: Some(self.context.project_id.clone()),
                repository: Some(self.context.repository.clone()),
                revision: 1,
                phase: device::Phase::CleanupUnknown,
                reason: device::Reason::CleanupUnknown,
                code: None,
                http: None,
            };
        };
        let phase = if f.unknown {
            device::Phase::CleanupUnknown
        } else if settled {
            if f.failure.is_some() {
                device::Phase::Failed
            } else {
                device::Phase::Settled
            }
        } else {
            f.phase
        };
        device::Status {
            schema_version: 1,
            document_revision: state.revision,
            connection_revision: state.github.snapshot().revision,
            available: available(document),
            operation_id: Some(self.context.operation_id.clone()),
            project_id: Some(self.context.project_id.clone()),
            repository: Some(self.context.repository.clone()),
            revision: f.revision,
            phase,
            reason: f.reason,
            code: if matches!(phase, device::Phase::Pending | device::Phase::Checking)
                && f.failure.is_none()
            {
                f.user_code.as_ref().map(|u| f.clock.code_view(u, now))
            } else {
                None
            },
            http: f.http.clone(),
        }
    }
    fn publish(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> Result<(), BridgeError> {
        let snapshot = self.snapshot(document, state);
        let response = self
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .response
            .clone();
        response.publish(snapshot)
    }
    // OriginalWork is traversed separately by the SAME Census. This only counts
    // these retained buffers. Live native tickets are never credited as gone.
    pub(super) fn data_bytes(&self) -> Option<usize> {
        if !self.active.try_lock().ok()?.is_none() || !self.http_wait.try_lock().ok()?.is_none() {
            return None;
        }
        let f = self.facts.try_lock().ok()?;
        if f.dispatch_attempted || f.call.is_some() || f.unknown {
            return None;
        }
        let mut n = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Facts>() + device::ENTRY_BACKING)?;
        n = n
            .checked_add(self.root.path.capacity())?
            .checked_add(self.context.operation_id.capacity())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.context.repository.capacity())?;
        n = n
            .checked_add(f.device_code.as_ref().map_or(0, |s| s.capacity()))?
            .checked_add(f.user_code.as_ref().map_or(0, String::capacity))?;
        if let Some(h) = &f.http {
            n = n
                .checked_add(h.session_id.capacity())?
                .checked_add(h.operation_id.capacity())?
        }
        if let Some(s) = &*f.response.0.try_lock().ok()? {
            n = n.checked_add(s.retained_bytes()?)?
        }
        Some(n)
    }
    pub(super) fn admitted_target(&self, context: &device::Context, end: Instant) -> bool {
        context == &self.context
            && self.active.try_lock().is_ok_and(|a| a.is_none())
            && self.facts.try_lock().is_ok_and(|f| {
                f.phase == device::Phase::Connecting
                    && f.call.is_none()
                    && !f.dispatch_attempted
                    && f.http_claimed
                    && !f.http_started
                    && !f.unknown
                    && f.failure.is_none()
                    && f.clock.end == end
                    && f.clock.handoff(Instant::now())
            })
    }
    pub(super) fn matches(&self, owner: &Arc<OriginalWork>, context: &device::Context) -> bool {
        Arc::ptr_eq(owner, &self.original) && context == &self.context
    }
}
fn original(state: &DocumentState) -> Option<&Arc<Registration>> {
    match &state.gh_auth {
        Some(Entry::Device(value)) => Some(value),
        _ => None,
    }
}
pub(in crate::asset_session) fn census_original(
    state: &DocumentState,
) -> Option<&Arc<OriginalWork>> {
    original(state).map(|r| &r.original)
}
pub(super) fn pending(state: &DocumentState) -> bool {
    original(state).is_some_and(|r| {
        !matches!(
            r.custody(),
            GitHubAuthCustody::Ready | GitHubAuthCustody::Refused(_)
        )
    })
}
pub(super) fn can_exit(state: &DocumentState) -> bool {
    original(state).is_none_or(|r| r.physically_settled())
}
pub(super) fn stop(state: &DocumentState, cause: GitHubReason) {
    if let Some(r) = original(state) {
        if !r.physically_settled() {
            r.stop(cause)
        }
    }
}
fn same_scope(
    document: &DocumentBinding,
    state: &mut DocumentState,
    r: &Registration,
) -> Result<(), BridgeError> {
    if !state.lifetime.original_bound()
        || state.lost_observed
        || state.stopping
        || state.unknown
        || !Arc::ptr_eq(&document.inner.session_identity, &r.session_identity)
        || state.session != r.native_session
        || match (&state.context, &r.native_context) {
            (None, None) => false,
            (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
            _ => true,
        }
    {
        return Err(stale());
    }
    let (generation, root) = document
        .registry_result(
            state,
            document.inner.bridge.native_project(&r.context.project_id),
            Some(&r.original),
        )
        .map_err(|e| source_error(e.reason))?;
    if generation != r.context.generation || root != r.root {
        return Err(stale());
    }
    let started = r
        .facts
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .http_started;
    if if started {
        !state.github.device_current(&r.original, &r.context)
    } else {
        state.github.gh_auth_idle_epoch() != Some(r.idle_connection_epoch)
    } {
        return Err(stale());
    }
    Ok(())
}
fn current(
    document: &DocumentBinding,
    state: &mut DocumentState,
    r: &Arc<Registration>,
    context: &device::Context,
) -> Result<(), BridgeError> {
    if !original(state).is_some_and(|other| Arc::ptr_eq(other, r))
        || context.operation_id != r.context.operation_id
        || context.project_id != r.context.project_id
        || context.repository != r.context.repository
        || context.generation != r.context.generation
    {
        return Err(stale());
    }
    if let Some(error) = r.error() {
        return Err(error);
    }
    same_scope(document, state, r)?;
    let base = document.github_base_gate(state);
    if base != GitHubReason::None {
        return Err(github_session::refused(base));
    }
    if !available(document) || !document.inner.bridge.edits.can_exit() || r.original.stopped() {
        return Err(stopped());
    }
    let f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
    if f.body_returned || Instant::now() >= f.clock.end {
        return Err(BridgeError::timeout());
    }
    if context.sequence != f.clock.polls {
        return Err(stale());
    }
    Ok(())
}
#[derive(Clone)]
pub(crate) struct GitHubDeviceGoGate {
    document: Weak<Inner>,
    registration: Weak<Registration>,
}
impl GitHubDeviceGoGate {
    fn originals(&self) -> Result<(DocumentBinding, Arc<Registration>), BridgeError> {
        Ok((
            DocumentBinding {
                inner: self.document.upgrade().ok_or_else(stopped)?,
            },
            self.registration.upgrade().ok_or_else(stopped)?,
        ))
    }
    pub(crate) fn failure(&self, error: BridgeError, at: Instant) {
        if let Some(r) = self.registration.upgrade() {
            r.failure(error, at)
        }
    }
    pub(crate) fn check_current(&self, context: &device::Context) -> Result<(), BridgeError> {
        let (d, r) = self.originals()?;
        let mut s = d.lock();
        let result = current(&d, &mut s, &r, context);
        if let Err(e) = &result {
            r.failure(e.clone(), Instant::now())
        }
        result
    }
    pub(crate) fn post(
        &self,
        context: &device::Context,
        role: device::Role,
        phase: GitHubDeviceSourcePost,
    ) -> Result<(), BridgeError> {
        let (d, r) = self.originals()?;
        let mut s = d.lock();
        current(&d, &mut s, &r, context)?;
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let call = f.call.as_mut().ok_or_else(stale)?;
        let (before, after) = match phase {
            GitHubDeviceSourcePost::Inspect => (Post::New, Post::Inspected),
            GitHubDeviceSourcePost::BeforeGo => (Post::Inspected, Post::Posted),
            GitHubDeviceSourcePost::AfterWork => (Post::Posted, Post::Returned),
        };
        if call.role != role || call.sequence != context.sequence || call.post != before {
            return Err(stale());
        }
        call.post = after;
        Ok(())
    }
    pub(crate) fn request(
        &self,
        context: &device::Context,
        id: &str,
        role: device::Role,
        clock: device::Clock,
    ) -> Result<device::Request, BridgeError> {
        let (d, r) = self.originals()?;
        let mut s = d.lock();
        current(&d, &mut s, &r, context)?;
        let f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !f.call.as_ref().is_some_and(|c| {
            c.role == role
                && c.sequence == context.sequence
                && c.post == Post::Inspected
                && c.request.is_none()
        }) {
            return Err(stale());
        }
        device::Request::new(
            id,
            role,
            context,
            device::configured().ok_or_else(unavailable)?,
            if role == device::Role::Poll {
                f.device_code.as_deref().map(|s| s.as_str())
            } else {
                None
            },
            clock,
        )
    }
    pub(crate) fn bind_request(
        &self,
        context: &device::Context,
        id: &str,
        request: Arc<device::Request>,
    ) -> Result<(), BridgeError> {
        let (d, r) = self.originals()?;
        let mut s = d.lock();
        current(&d, &mut s, &r, context)?;
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let call = f.call.as_mut().ok_or_else(stale)?;
        if call.post != Post::Inspected
            || call.request.is_some()
            || call.role != request.role()
            || call.sequence != context.sequence
        {
            return Err(stale());
        }
        call.request = Some((id.into(), request));
        Ok(())
    }
    pub(crate) fn claim(
        &self,
        id: &str,
        digest: &str,
        context: &device::Context,
        role: device::Role,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let (d, r) = self.originals()?;
        let mut s = d.lock();
        current(&d, &mut s, &r, context)?;
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let call = f.call.as_mut().ok_or_else(stale)?;
        let (known, request) = call.request.as_ref().ok_or_else(stale)?;
        if known != id
            || request.digest() != digest
            || call.post != Post::Posted
            || call.go
            || call.role != role
            || call.sequence != context.sequence
        {
            return Err(stale());
        }
        call.go = true;
        if !claim() {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(request.go())
    }
}
fn admission_budget(
    document: &DocumentBinding,
    state: &DocumentState,
    original: Option<&Arc<OriginalWork>>,
    future: usize,
) -> Result<(), BridgeError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    {
        match original {
            Some(owner) => {
                lookup_memory::github_device_admission_bytes(&document.inner, state, owner, future)
            }
            None => lookup_memory::github_auth_admission_bytes(&document.inner, state, future),
        }
        .map(|_| ())
        .map_err(|_| busy())
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )))]
    {
        let _ = (document, state, original, future);
        Err(BridgeError::unavailable(
            "The installed device runtime is unavailable.",
        ))
    }
}
fn available(document: &DocumentBinding) -> bool {
    cfg!(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    )) && device::configured().is_some()
        && document.native_qualified()
        && document.github_qualified()
        && document
            .inner
            .bridge
            .supervisor
            .github_device_profile_available()
}
fn idle(
    document: &DocumentBinding,
    state: &DocumentState,
    reason: device::Reason,
) -> device::Status {
    device::Status {
        schema_version: 1,
        document_revision: state.revision,
        connection_revision: state.github.snapshot().revision,
        available: available(document),
        operation_id: None,
        project_id: None,
        repository: None,
        revision: 1,
        phase: device::Phase::Idle,
        reason,
        code: None,
        http: None,
    }
}
fn status(document: &DocumentBinding, state: &DocumentState) -> device::Status {
    match &state.gh_auth {
        Some(Entry::Device(r)) => r.snapshot(document, state),
        Some(Entry::DeviceFinished(s)) => device::Status {
            available: available(document),
            document_revision: state.revision,
            connection_revision: state.github.snapshot().revision,
            ..s.clone()
        },
        _ => idle(
            document,
            state,
            if device::configured().is_none() {
                device::Reason::PublisherUnconfigured
            } else if available(document) {
                device::Reason::None
            } else {
                device::Reason::RuntimeUnavailable
            },
        ),
    }
}
pub(super) fn observe(document: &DocumentBinding, state: &mut DocumentState, now: Instant) {
    let Some(r) = original(state).cloned() else {
        return;
    };
    if r.original.join_if_ended() == Some(false) {
        r.failure(BridgeError::cleanup_unknown(), now)
    }
    if r.error().is_none() {
        if let Err(error) = same_scope(document, state, &r) {
            r.failure(error, now)
        }
    }
    let (end, hard) = r.facts.lock().map_or((now, now), |f| {
        (f.clock.end, f.clock.cleanup.unwrap_or(f.clock.hard))
    });
    if now >= end && r.error().is_none() {
        r.failure(BridgeError::timeout(), end)
    }
    if now >= hard && !r.physically_settled() {
        r.failure(BridgeError::cleanup_unknown(), now)
    }
    if r.error().is_some() {
        if let Ok(active) = r.active.try_lock() {
            if let Some(active) = &*active {
                active.wait.stop()
            }
        }
        if let Ok(http) = r.http_wait.try_lock() {
            if let Some(http) = &*http {
                http.stop()
            }
        }
    }
    if r.facts.try_lock().is_ok_and(|f| f.unknown) {
        state.unknown = true;
        state.github.unknown();
        let _ = r.publish(document, state);
    }
}
pub(super) fn retire(document: &DocumentBinding, state: &mut DocumentState) {
    let Some(r) = original(state).cloned() else {
        return;
    };
    if !matches!(
        r.custody(),
        GitHubAuthCustody::Ready | GitHubAuthCustody::Refused(_)
    ) || state.github.device_retains(&r.original, &r.context)
    {
        return;
    }
    let snapshot = r.snapshot(document, state);
    if r.publish(document, state).is_err() {
        r.failure(BridgeError::cleanup_unknown(), Instant::now());
        state.unknown = true;
        return;
    }
    state.gh_auth = Some(Entry::DeviceFinished(snapshot));
}
impl DocumentBinding {
    pub(crate) fn github_device_status(&self) -> device::Status {
        let mut s = self.lock();
        self.expire(&mut s, Instant::now());
        status(self, &s)
    }
    pub(crate) fn github_device_cancel(&self, id: &str) -> Result<device::Status, BridgeError> {
        let mut s = self.lock();
        // A late Stop can overtake the original invoke's return after native
        // retirement. Return only that exact already-joined historical result;
        // never cancel a successor or invent a new completed operation.
        if matches!(&s.gh_auth, Some(Entry::DeviceFinished(done)) if done.operation_id.as_deref()==Some(id))
        {
            return Ok(status(self, &s));
        }
        let r = original(&s)
            .filter(|r| r.context.operation_id == id)
            .cloned()
            .ok_or_else(stale)?;
        r.stop(GitHubReason::Cancelled);
        self.bump(&mut s);
        Ok(status(self, &s))
    }
    pub(crate) fn github_device_start(
        &self,
        request: device::Start,
    ) -> Result<Observer, BridgeError> {
        device::configured().ok_or_else(unavailable)?;
        if !request.valid() {
            return Err(BridgeError::invalid());
        }
        if !available(self) {
            return Err(BridgeError::unavailable(
                "The installed device runtime is unavailable.",
            ));
        }
        #[cfg(feature = "desktop-shell")]
        {
            self.github_device_start_desktop(request)
        }
        #[cfg(not(feature = "desktop-shell"))]
        {
            Err(BridgeError::unavailable(
                "The installed device runtime is unavailable.",
            ))
        }
    }
    #[cfg(feature = "desktop-shell")]
    fn github_device_start_desktop(
        &self,
        request: device::Start,
    ) -> Result<Observer, BridgeError> {
        let mut s = self.lock();
        self.expire(&mut s, Instant::now());
        let base = self.github_gate(&s);
        if base != GitHubReason::None {
            return Err(github_session::refused(base));
        }
        if request.expected_document_revision != s.revision
            || request.expected_connection_revision != s.github.snapshot().revision
        {
            return Err(stale());
        }
        if !self.inner.bridge.supervisor.can_exit()
            || !self.inner.bridge.edits.can_exit()
            || s.github.registration().is_some()
        {
            return Err(busy());
        }
        let idle_connection_epoch = s.github.gh_auth_idle_epoch().ok_or_else(busy)?;
        let (generation, root) = self
            .registry_result(
                &mut s,
                self.inner.bridge.native_project(&request.project_id),
                None,
            )
            .map_err(|e| source_error(e.reason))?;
        let future = GitHubDeviceAdmission::reservation_bytes()
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<OriginalWork>()
                        + std::mem::size_of::<Registration>()
                        + device::ENTRY_BACKING,
                )
            })
            .ok_or_else(BridgeError::invalid)?;
        admission_budget(self, &s, None, future)?;
        let id = self
            .next_operation(&mut s)
            .map_err(|e| source_error(e.reason))?;
        let now = Instant::now();
        let clock = Clock::new(now).ok_or_else(BridgeError::invalid)?;
        let work = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        work.set_endpoint(Some(clock.end));
        let response = Arc::new(ReplySlot(Mutex::new(None)));
        let observer = Observer {
            document: Arc::downgrade(&self.inner),
            response: response.clone(),
            hard: clock.hard,
        };
        let r = Arc::new(Registration {
            original: work.clone(),
            document: Arc::downgrade(&self.inner),
            session_identity: self.inner.session_identity.clone(),
            native_context: s.context.clone(),
            native_session: s.session,
            idle_connection_epoch,
            root,
            context: device::Context {
                operation_id: id.to_string(),
                project_id: request.project_id,
                repository: request.repository,
                generation,
                sequence: 0,
            },
            facts: Mutex::new(Facts {
                phase: device::Phase::Starting,
                revision: 1,
                reason: device::Reason::None,
                clock,
                failure: None,
                unknown: false,
                command: Some(device::Role::Start),
                call: None,
                dispatch_attempted: false,
                device_code: None,
                user_code: None,
                response,
                http_claimed: false,
                http_started: false,
                http_settled: false,
                http: None,
                body_returned: false,
                final_join: None,
            }),
            active: Mutex::new(None),
            http_wait: Mutex::new(None),
        });
        let mut coordinator = work
            .coordinator
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let (start, enter) = oneshot::channel();
        coordinator.receipt = JoinReceipt::Pending;
        s.gh_auth = Some(Entry::Device(r.clone()));
        let document = self.clone();
        let guard = Body {
            registration: r.clone(),
            _end: CoordinatorEnd(work.clone()),
            normal: false,
        };
        coordinator.handle = Some(tauri::async_runtime::spawn(async move {
            let mut guard = guard;
            if enter.await.is_err() {
                r.failure(BridgeError::cleanup_unknown(), Instant::now())
            } else {
                coordinate(&document, &r).await;
            }
            if let Ok(mut f) = r.facts.lock() {
                f.body_returned = true;
                f.device_code = None;
                f.user_code = None;
                let _ = Registration::step(&mut f);
            }
            guard.normal = true;
        }));
        drop(coordinator);
        if start.send(()).is_err() {
            work.signal_stop()
        }
        self.bump(&mut s);
        Ok(observer)
    }
    pub(crate) fn github_device_check(
        &self,
        selected: device::Selected,
    ) -> Result<Observer, BridgeError> {
        let mut s = self.lock();
        self.expire(&mut s, Instant::now());
        let r = original(&s).cloned().ok_or_else(stale)?;
        current(self, &mut s, &r, &r.context_with_sequence()?)?;
        if selected.operation_id != r.context.operation_id {
            return Err(stale());
        }
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if f.revision != selected.revision
            || f.phase != device::Phase::Pending
            || f.command.is_some()
            || f.call.is_some()
            || f.dispatch_attempted
            || f.device_code.is_none()
        {
            return Err(busy());
        }
        f.clock.poll(Instant::now())?;
        let response = Arc::new(ReplySlot(Mutex::new(None)));
        f.response = response.clone();
        f.phase = device::Phase::Checking;
        f.reason = device::Reason::None;
        f.command = Some(device::Role::Poll);
        Registration::step(&mut f)?;
        let hard = f.clock.hard;
        drop(f);
        self.bump(&mut s);
        r.original.wake.notify_waiters();
        Ok(Observer {
            document: Arc::downgrade(&self.inner),
            response,
            hard,
        })
    }
    pub(crate) fn github_device_open(&self, selected: device::Selected) -> Result<(), BridgeError> {
        let mut s = self.lock();
        self.expire(&mut s, Instant::now());
        let r = original(&s).cloned().ok_or_else(stale)?;
        current(self, &mut s, &r, &r.context_with_sequence()?)?;
        {
            let f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if selected.operation_id != r.context.operation_id
                || selected.revision != f.revision
                || f.phase != device::Phase::Pending
                || f.device_code.is_none()
            {
                return Err(stale());
            }
        }
        // Synchronous original main-thread native request; the fixed URL has no code.
        // No async owner, grant, file, token or observer receipt is manufactured.
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            if mrk_macos_installed_native::github_browser::open_device().is_err() {
                return Err(BridgeError::unavailable(
                    "The browser request was unavailable.",
                ));
            }
            Ok(())
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            Err(BridgeError::unavailable(
                "The browser request is unavailable.",
            ))
        }
    }
}
impl Registration {
    fn context_with_sequence(&self) -> Result<device::Context, BridgeError> {
        let mut c = self.context.clone();
        c.sequence = self
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clock
            .polls;
        Ok(c)
    }
}
struct Body {
    registration: Arc<Registration>,
    _end: CoordinatorEnd,
    normal: bool,
}
impl Drop for Body {
    fn drop(&mut self) {
        if !self.normal {
            self.registration
                .failure(BridgeError::cleanup_unknown(), Instant::now())
        }
    }
}
async fn coordinate(document: &DocumentBinding, r: &Arc<Registration>) {
    loop {
        if r.error().is_some() {
            break;
        }
        let wake = r.original.wake.notified();
        // Drop either the returned guard or the poisoned-lock payload before
        // calling failure(), which must acquire the SAME facts mutex.
        let role = r
            .facts
            .lock()
            .map(|mut f| f.command.take())
            .map_err(|_| BridgeError::cleanup_unknown());
        let role = match role {
            Ok(role) => role,
            Err(error) => {
                r.failure(error, Instant::now());
                break;
            }
        };
        let Some(role) = role else {
            let end = r.bound();
            tokio::select! {biased;_=wake=>{},_=tokio::time::sleep_until(tokio::time::Instant::from_std(end))=>r.failure(BridgeError::timeout(),end)};
            continue;
        };
        let result = exchange(document, r, role).await;
        match result {
            Ok((
                device::Reply::Code {
                    device: code,
                    user,
                    expires,
                    interval,
                },
                admitted,
            )) => {
                let update = (|| {
                    let mut s = document.lock();
                    let context = r.context_with_sequence()?;
                    current(document, &mut s, r, &context)?;
                    let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    f.clock.code(admitted, Instant::now(), expires, interval)?;
                    r.original.set_endpoint(Some(f.clock.end));
                    f.device_code = Some(code);
                    f.user_code = Some(user);
                    f.phase = device::Phase::Pending;
                    f.reason = device::Reason::Waiting;
                    Registration::step(&mut f)?;
                    drop(f);
                    document.bump(&mut s);
                    r.publish(document, &s)
                })();
                if let Err(error) = update {
                    r.failure(error, Instant::now());
                    break;
                }
            }
            Ok((reply @ (device::Reply::Pending | device::Reply::SlowDown), _)) => {
                let slow = matches!(reply, device::Reply::SlowDown);
                let update = (|| {
                    let mut s = document.lock();
                    current(document, &mut s, r, &r.context_with_sequence()?)?;
                    let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    f.clock.pending(Instant::now(), slow)?;
                    f.phase = device::Phase::Pending;
                    f.reason = if slow {
                        device::Reason::SlowDown
                    } else {
                        device::Reason::Waiting
                    };
                    Registration::step(&mut f)?;
                    drop(f);
                    document.bump(&mut s);
                    r.publish(document, &s)
                })();
                if let Err(error) = update {
                    r.failure(error, Instant::now());
                    break;
                }
            }
            Ok((device::Reply::Token { token, expires }, admitted)) => {
                if let Err(error) = handoff(document, r, token, expires, admitted).await {
                    r.failure(error, Instant::now())
                }
                break;
            }
            Ok((device::Reply::Refused(reason), _)) => {
                r.failure(provider_refusal(reason), Instant::now());
                break;
            }
            Err(error) => {
                r.failure(error, Instant::now());
                break;
            }
        }
    }
}
async fn exchange(
    document: &DocumentBinding,
    r: &Arc<Registration>,
    role: device::Role,
) -> Result<(device::Reply, Instant), BridgeError> {
    let context = r.context_with_sequence()?;
    let end = {
        let mut s = document.lock();
        current(document, &mut s, r, &context)?;
        let future = GitHubDeviceAdmission::reservation_bytes().ok_or_else(BridgeError::invalid)?;
        admission_budget(document, &s, Some(&r.original), future)?;
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if f.call.is_some() || f.dispatch_attempted {
            return Err(BridgeError::cleanup_unknown());
        }
        f.call = Some(Call {
            role,
            sequence: context.sequence,
            admitted: Instant::now(),
            post: Post::New,
            request: None,
            go: false,
        });
        f.clock.end
    };
    let admission = GitHubDeviceAdmission::reserve(r.gate(), context.clone(), role, end)?;
    {
        r.facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .dispatch_attempted = true;
    }
    let ticket = match document
        .inner
        .bridge
        .supervisor
        .start_github_device(admission)
    {
        Ok(v) => v,
        Err(error) => {
            let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            f.dispatch_attempted = false;
            f.call = None;
            return Err(error);
        }
    };
    let wait = Arc::new(ticket.wait_handle());
    {
        let mut active = r
            .active
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if active.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *active = Some(Active {
            ticket,
            wait: wait.clone(),
        });
    }
    {
        let returned = wait.returned();
        tokio::pin!(returned);
        loop {
            let wake = r.original.wake.notified();
            let end = r.bound();
            let outcome = tokio::select! {biased;v=&mut returned=>Some(v),_=wake=>None,_=tokio::time::sleep_until(tokio::time::Instant::from_std(end))=>{r.failure(BridgeError::cleanup_unknown(),end);return Err(BridgeError::cleanup_unknown())}};
            if r.error().is_some() {
                wait.stop()
            }
            if let Some(outcome) = outcome {
                if outcome != GitHubAuthReceipt::Settled {
                    return Err(BridgeError::cleanup_unknown());
                }
                break;
            }
        }
    }
    let active = r
        .active
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .take()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    if !Arc::ptr_eq(&active.wait, &wait)
        || active.ticket.context() != &context
        || active.ticket.role() != role
    {
        return Err(BridgeError::cleanup_unknown());
    }
    let result = active.ticket.consume();
    drop(active.wait);
    drop(wait); // Actual observer joined; no old runtime retained for the next phase.
    let admitted = {
        let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        f.dispatch_attempted = false;
        let call = f.call.take().ok_or_else(BridgeError::cleanup_unknown)?;
        if result.is_ok() && (call.post != Post::Returned || !call.go) {
            return Err(BridgeError::cleanup_unknown());
        }
        call.admitted
    };
    Ok((result?, admitted))
}
async fn handoff(
    document: &DocumentBinding,
    r: &Arc<Registration>,
    mut token: Zeroizing<String>,
    expires: Option<u32>,
    admitted: Instant,
) -> Result<(), BridgeError> {
    let wait = {
        let mut s = document.lock();
        current(document, &mut s, r, &r.context_with_sequence()?)?;
        let future = GitHubDeviceAdmission::reservation_bytes().ok_or_else(BridgeError::invalid)?;
        admission_budget(document, &s, Some(&r.original), future)?;
        let end = {
            let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if !f.clock.handoff(Instant::now()) || f.http_claimed {
                return Err(BridgeError::timeout());
            }
            f.phase = device::Phase::Connecting;
            f.device_code = None;
            f.user_code = None;
            f.http_claimed = true;
            Registration::step(&mut f)?;
            f.clock.end
        };
        let expiry = expires
            .map(|seconds| {
                admitted
                    .checked_add(Duration::from_secs(u64::from(seconds)))
                    .ok_or_else(BridgeError::timeout)
            })
            .transpose()?;
        // As for selected-gh, this SAME original holds Document admission.
        // Public capability reconciliation while it was pending may say Busy;
        // do not mistake our own retained original for a foreign operation.
        let external = document.github_base_gate(&s);
        s.github.reconcile(Instant::now(), external);
        let hold = GitHubAuthConnectionHold::Device(r.clone());
        let result = s.github.connect_device(
            r.context.clone(),
            std::mem::take(&mut *token),
            expiry,
            end,
            hold,
            &document.inner.bridge.supervisor,
            Instant::now(),
            SystemTime::now(),
        )?;
        // No public outcome manufactures these IDs; only the actual same original synchronous admission did.
        let http = result
            .session
            .as_ref()
            .zip(result.operation.as_ref())
            .map(|(session, operation)| device::Http {
                session_id: session.id.clone(),
                operation_id: operation.id.clone(),
            })
            .ok_or_else(BridgeError::cleanup_unknown)?;
        {
            let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            f.http_started = true;
            f.http = Some(http);
        }
        let wait = Arc::new(
            s.github
                .device_wait(&r.original, &r.context)
                .ok_or_else(BridgeError::cleanup_unknown)?,
        );
        *r.http_wait
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())? = Some(wait.clone());
        document.bump(&mut s);
        wait
    };
    {
        let returned = wait.returned();
        tokio::pin!(returned);
        loop {
            let wake = r.original.wake.notified();
            let end = r.bound();
            let result = tokio::select! {biased;value=&mut returned=>Some(value),_=wake=>None,_=tokio::time::sleep_until(tokio::time::Instant::from_std(end))=>{return Err(BridgeError::cleanup_unknown())}};
            if r.error().is_some() {
                wait.stop()
            }
            if let Some(result) = result {
                if result != GitHubAuthReceipt::Settled {
                    return Err(BridgeError::cleanup_unknown());
                }
                break;
            }
        }
    }
    r.http_wait
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .take();
    drop(wait);
    r.facts
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .http_settled = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> device::Context {
        device::Context {
            operation_id: "1".into(),
            project_id: "inert-project".into(),
            repository: "fixture/repository".into(),
            generation: 1,
            sequence: 0,
        }
    }
    #[test]
    fn absent_original_gate_cannot_mint_device_request_or_claim_go() {
        let gate = GitHubDeviceGoGate {
            document: Weak::new(),
            registration: Weak::new(),
        };
        let context = context();
        assert!(gate.check_current(&context).is_err());
        assert!(gate
            .request(
                &context,
                "inert-child",
                device::Role::Start,
                device::Clock {
                    work_end_ns: 1,
                    hard_end_ns: 2
                }
            )
            .is_err());
        let called = std::cell::Cell::new(false);
        assert!(gate
            .claim(
                "inert-child",
                &"a".repeat(64),
                &context,
                device::Role::Start,
                || {
                    called.set(true);
                    true
                }
            )
            .is_err());
        assert!(!called.get());
        let slot = ReplySlot(Mutex::new(None));
        let over = device::Status {
            schema_version: 1,
            document_revision: 1,
            connection_revision: 1,
            available: false,
            operation_id: Some(String::with_capacity(RETURN_DATA_BYTES + 1)),
            project_id: None,
            repository: None,
            revision: 1,
            phase: device::Phase::Idle,
            reason: device::Reason::PublisherUnconfigured,
            code: None,
            http: None,
        };
        assert!(slot.publish(over).is_err());
        assert!(slot.take().unwrap().is_none());
        assert!(
            121usize
                .checked_mul(
                    RETURN_DATA_BYTES
                        + std::mem::size_of::<ReplySlot>()
                        + std::mem::size_of::<Observer>()
                        + 64
                )
                .unwrap()
                <= device::ENTRY_BACKING
        );
    }
    // In-memory original/Document behavior is shared with the Mac LP64 graph;
    // these cases do not enter a platform runtime or supply a native receipt.
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))
    ))]
    #[test]
    fn missing_client_id_refuses_before_document_original_or_runtime_entry() {
        let bridge = Arc::new(DesktopBridge::new("/unopened-device-prerequisite".into()));
        let document = DocumentBinding::new(bridge.clone());
        let before = document.lock().revision;
        let result = document.github_device_start(device::Start {
            project_id: "inert-project".into(),
            repository: "fixture/repository".into(),
            expected_document_revision: 1,
            expected_connection_revision: 1,
            consent_version: device::CONSENT.into(),
        });
        assert!(matches!(result,Err(error) if error.code=="device_unconfigured"));
        let state = document.lock();
        assert_eq!(state.revision, before);
        assert!(state.gh_auth.is_none());
        assert!(state.github.registration().is_none() && bridge.supervisor.can_exit());
    }
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))
    ))]
    #[test]
    fn pending_device_original_keeps_peer_exclusion_and_stop_cannot_fake_finality() {
        // Same actual in-memory Document/OriginalWork predicates as gh tests.
        // No native admission, child, HTTP account or positive join is supplied.
        let bridge = Arc::new(DesktopBridge::new(
            "/unopened-device-peer-regression".into(),
        ));
        let document = DocumentBinding::new(bridge.clone());
        document.hook_installed();
        document.observe(|l| l.started(true));
        document.observe(|l| l.finished(true));
        let original = OriginalWork::new(1, false, Arc::downgrade(&document.inner));
        let clock = Clock::new(Instant::now()).unwrap();
        original.set_endpoint(Some(clock.end));
        let r = Arc::new(Registration {
            original,
            document: Arc::downgrade(&document.inner),
            session_identity: document.inner.session_identity.clone(),
            native_context: None,
            native_session: false,
            idle_connection_epoch: 1,
            root: asset_source::RegisteredRoot {
                path: "/unopened-device-project".into(),
                identity: asset_source::ProjectIdentity::Posix(
                    asset_source::DirectoryIdentity::synthetic_evidence_identity(),
                ),
            },
            context: context(),
            active: Mutex::new(None),
            http_wait: Mutex::new(None),
            facts: Mutex::new(Facts {
                phase: device::Phase::Pending,
                revision: 2,
                reason: device::Reason::Waiting,
                clock,
                failure: None,
                unknown: false,
                command: None,
                call: None,
                dispatch_attempted: false,
                device_code: Some(Zeroizing::new("inert-device-code".into())),
                user_code: Some("ABCD-1234".into()),
                response: Arc::new(ReplySlot(Mutex::new(None))),
                http_claimed: false,
                http_started: false,
                http_settled: false,
                http: None,
                body_returned: false,
                final_join: None,
            }),
        });
        {
            let mut s = document.lock();
            s.gh_auth = Some(Entry::Device(r.clone()));
            assert!(super::super::pending(&s));
            assert!(!can_exit(&s));
            assert!(passive_document_gate(&s).is_err());
        }
        let stopped = document.github_device_cancel("1").unwrap();
        assert!(
            stopped.phase == device::Phase::Stopping
                && stopped.reason == device::Reason::Cancelled
                && stopped.code.is_none()
        );
        assert!(r.original.interrupted());
        assert!(!r.physically_settled());
        assert!(matches!(r.custody(), GitHubAuthCustody::Pending));
        r.failure(BridgeError::cleanup_unknown(), Instant::now());
        let s = document.lock();
        assert!(pending(&s));
        assert!(!can_exit(&s));
        assert!(matches!(r.custody(), GitHubAuthCustody::Unknown));
        assert!(s.github.registration().is_none());
    }
}
