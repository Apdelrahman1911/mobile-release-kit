//! Selected official gh under the SAME actual Document and OriginalWork.
//! There is no renderer credential, alternate command executor, service DTO
//! admission, PATH discovery, or substitute History provider. This entry stays
//! unavailable without the distinct installed stock nomination/profile.
use super::*;
#[path = "asset_session_gh_auth_accounts.rs"]
mod accounts;
use crate::{
    github_auth_capture_wire as wire, github_auth_entry_protocol as entry_wire,
    github_auth_native_owner::NativeGhProvider,
    github_connection_session::auth_provider,
    supervisor::{
        GitHubAuthAdmission, GitHubAuthHttpWait, GitHubAuthReceipt, GitHubAuthSourcePost,
        GitHubAuthWait,
    },
};
pub(crate) use entry_wire::{
    Connect as GitHubAuthRequest, Phase as GitHubAuthPhase, Status as GitHubAuthStatus,
};
use std::path::PathBuf;

const WHOLE: Duration = Duration::from_secs(60);
const FAILURE_CLEANUP: Duration = Duration::from_secs(10);

// Only a positively joined original may be replaced by this bounded public
// history. Keeping the whole retired Supervisor here would also keep its
// closed runtime inventory allocation alive during a later operation.
pub(super) enum Entry {
    Original(Arc<Registration>),
    Finished(GitHubAuthStatus),
    Accounts(Arc<accounts::Read>),
    AccountsFinished(accounts::Finished),
}
impl Entry {
    fn original(&self) -> Option<&Arc<Registration>> {
        match self {
            Self::Original(original) => Some(original),
            Self::Finished(_) | Self::Accounts(_) | Self::AccountsFinished(_) => None,
        }
    }
}

/// Bounded historical response DATA only. There is deliberately no strong or
/// weak native owner/runtime/SourceBook/HTTPWait reference in this slot. A late
/// or dropped invoke may keep this small value, never the retired runtime whose
/// working debit the Document has released. Native lifetime belongs to Entry.
struct ResultSlot(Mutex<ResultFacts>);
struct ResultFacts {
    last: GitHubAuthStatus,
    result: Option<entry_wire::ConnectResult>,
    consumed: bool,
}
impl ResultSlot {
    fn new(last: GitHubAuthStatus) -> Self {
        Self(Mutex::new(ResultFacts {
            last,
            result: None,
            consumed: false,
        }))
    }
    fn observe(&self, status: GitHubAuthStatus) -> Result<(), BridgeError> {
        if status.retained_bytes().is_none_or(|bytes| bytes > 8192) {
            return Err(BridgeError::cleanup_unknown());
        }
        let mut facts = self.0.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if status.operation_id != facts.last.operation_id
            || status.project_id != facts.last.project_id
            || status.repository != facts.last.repository
            || status.selected_login != facts.last.selected_login
            || facts
                .last
                .http
                .as_ref()
                .is_some_and(|http| status.http.as_ref() != Some(http))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        facts.last = status;
        Ok(())
    }
    /// Sole production caller is the actual successful same-Document HTTP
    /// admission after its original wait/hold was retained. This checks DATA
    /// consistency, not admission. No public status can call this constructor.
    fn handoff(
        &self,
        connection: crate::github_connection_protocol::Status,
    ) -> Result<entry_wire::HttpHandoff, BridgeError> {
        use crate::github_connection_protocol::{OperationKind, Phase, SessionState};
        let mut facts = self.0.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if facts.result.is_some() || facts.consumed || facts.last.http.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        let session = connection
            .session
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let operation = connection
            .operation
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if Some(&session.project_id) != facts.last.project_id.as_ref()
            || Some(&session.target_repository) != facts.last.repository.as_ref()
            || session.state != SessionState::Checking
            || operation.kind != OperationKind::Connect
            || operation.phase != Phase::Running
            || operation.reason != GitHubReason::None
            || !crate::protocol::valid_id(&session.id)
            || !crate::protocol::valid_id(&operation.id)
            || serde_json::to_vec(&connection).map_or(true, |bytes| {
                bytes.len() > crate::github_connection_protocol::STATUS_LIMIT
            })
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let http = entry_wire::HttpHandoff {
            session_id: session.id.clone(),
            operation_id: operation.id.clone(),
        };
        let operation_id = facts
            .last
            .operation_id
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        facts.last.http = Some(http.clone());
        facts.result = Some(entry_wire::ConnectResult {
            schema_version: 1,
            operation_id,
            outcome: entry_wire::Outcome::HttpHandoff { connection },
        });
        Ok(http)
    }
    fn terminal(&self, known_no_http: bool) -> Result<(), BridgeError> {
        let mut facts = self.0.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if facts.result.is_some() || facts.consumed {
            return Ok(());
        }
        let mut auth = facts.last.clone();
        let operation_id = auth
            .operation_id
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let outcome =
            if known_no_http && auth.http.is_none() && auth.phase == GitHubAuthPhase::Failed {
                entry_wire::Outcome::NoHttp { auth }
            } else {
                // No synthetic no-send proof on lost Document, uncertain claim,
                // poisoned/missing data, timeout or incomplete actual settlement.
                auth.phase = GitHubAuthPhase::CleanupUnknown;
                auth.reason = GitHubReason::CleanupUnknown;
                entry_wire::Outcome::Unknown { auth }
            };
        facts.result = Some(entry_wire::ConnectResult {
            schema_version: 1,
            operation_id,
            outcome,
        });
        Ok(())
    }
    fn take(&self) -> Result<Option<entry_wire::ConnectResult>, BridgeError> {
        let mut facts = self.0.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if facts.consumed {
            return Err(BridgeError::cleanup_unknown());
        }
        if facts.result.is_none() {
            return Ok(None);
        }
        facts.consumed = true;
        Ok(facts.result.take())
    }
}
fn no_http_proved(custody: GitHubAuthCustody, claimed: bool) -> bool {
    !claimed
        && matches!(custody, GitHubAuthCustody::Refused(reason)
        if !matches!(reason, GitHubReason::None | GitHubReason::CleanupUnknown))
}

/// Consume-only observer, not an operation owner. It never retains Registration
/// or OriginalWork; each actual Document observation is released before await.
pub(crate) struct GitHubAuthConnectObserver {
    document: Weak<Inner>,
    result: Arc<ResultSlot>,
}
impl GitHubAuthConnectObserver {
    pub(crate) async fn returned(self) -> Result<entry_wire::ConnectResult, BridgeError> {
        loop {
            if let Some(result) = self.result.take()? {
                return Ok(result);
            }
            if let Some(inner) = self.document.upgrade() {
                let document = DocumentBinding { inner };
                // Actual expiry/reconciliation publishes terminal no-HTTP only
                // after original joins. No guard/native owner crosses sleep.
                document.github_auth_status();
            } else {
                self.result.terminal(false)?;
            }
            if let Some(result) = self.result.take()? {
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Picking,
    Sources,
    Version,
    Token,
    BeforeHttp,
    Http,
    Closing,
    BodyReturned,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PostState {
    New,
    Inspecting,
    Inspected,
    BeforeGo,
    Posted,
    AfterWork,
    Returned,
}
struct RoleBook {
    post: PostState,
    request: Option<(String, Arc<wire::Request>)>,
    go: bool,
}
impl RoleBook {
    fn new() -> Self {
        Self {
            post: PostState::New,
            request: None,
            go: false,
        }
    }
    fn begin(&mut self, phase: GitHubAuthSourcePost) -> bool {
        let (expected, next) = match phase {
            GitHubAuthSourcePost::Inspect => (PostState::New, PostState::Inspecting),
            GitHubAuthSourcePost::BeforeGo => (PostState::Inspected, PostState::BeforeGo),
            GitHubAuthSourcePost::AfterWork => (PostState::Posted, PostState::AfterWork),
        };
        if self.post != expected
            || phase != GitHubAuthSourcePost::Inspect && self.request.is_none()
            || phase == GitHubAuthSourcePost::AfterWork && !self.go
        {
            return false;
        }
        self.post = next;
        true // Retain entered state before any native call.
    }
    fn returned(&mut self, phase: GitHubAuthSourcePost) -> bool {
        let (expected, next) = match phase {
            GitHubAuthSourcePost::Inspect => (PostState::Inspecting, PostState::Inspected),
            GitHubAuthSourcePost::BeforeGo => (PostState::BeforeGo, PostState::Posted),
            GitHubAuthSourcePost::AfterWork => (PostState::AfterWork, PostState::Returned),
        };
        if self.post != expected {
            return false;
        }
        self.post = next;
        true
    }
}
struct Facts {
    stage: Stage,
    failure: Option<(BridgeError, Instant)>,
    cleanup_end: Option<Instant>,
    unknown: bool,
    consent_live: bool,
    http_claimed: bool,
    http_started: bool,
    http_handoff: Option<entry_wire::HttpHandoff>,
    source_entered: bool,
    source_returned: bool,
    before_http_entered: bool,
    before_http_returned: bool,
    finish_entered: bool,
    close_entered: bool,
    body_returned: bool,
    final_join: Option<Instant>,
    roles: [RoleBook; 2],
}
pub(super) struct Registration {
    original: Arc<OriginalWork>,
    document: Weak<Inner>,
    session_identity: Arc<()>,
    native_context: Option<Arc<NativeContext>>,
    native_session: bool,
    idle_connection_epoch: u32,
    root: asset_source::RegisteredRoot,
    request: GitHubAuthRequest,
    accounts_witness: Option<crate::github_auth_accounts::Witness>,
    // Only the actual SAME original GUI may fill this cell, after its native
    // close/release dispatches join. This is not supplied by the command DTO.
    physical_executable: Mutex<Option<PathBuf>>,
    result: Arc<ResultSlot>,
    context: wire::Context,
    end: Instant,
    facts: Mutex<Facts>,
    provider: Mutex<Option<NativeGhProvider>>,
    active: Mutex<Option<Arc<GitHubAuthWait>>>,
    http: Mutex<Option<Arc<GitHubAuthHttpWait>>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    sources: Mutex<asset_source::GhAuthSources>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    nomination: crate::github_auth_nomination::StockGhNomination,
}
fn role_index(role: wire::Role) -> usize {
    if role == wire::Role::Version {
        0
    } else {
        1
    }
}
fn changed() -> BridgeError {
    github_session::refused(GitHubReason::TargetChanged)
}
fn cancelled() -> BridgeError {
    github_session::refused(GitHubReason::Cancelled)
}
fn is_unknown(error: &BridgeError) -> bool {
    matches!(
        error.code.as_str(),
        "cleanup_unknown" | "github_connection_refused_cleanup_unknown"
    )
}
fn reason(error: &BridgeError) -> GitHubReason {
    match error.code.as_str() {
        "target_changed" | "github_connection_refused_target_changed" => {
            GitHubReason::TargetChanged
        }
        "cancelled" | "shutting_down" | "github_connection_refused_cancelled" => {
            GitHubReason::Cancelled
        }
        "query_timeout" | "github_connection_refused_expired" => GitHubReason::Expired,
        "runtime_unavailable" | "github_connection_refused_runtime_unavailable" => {
            GitHubReason::RuntimeUnavailable
        }
        "github_connection_refused_unqualified" => GitHubReason::RuntimeUnavailable,
        "busy" | "github_connection_refused_busy" => GitHubReason::Busy,
        "invalid_request" | "github_connection_refused_invalid_input" => GitHubReason::InvalidInput,
        "github_connection_refused_response_invalid" => GitHubReason::ResponseInvalid,
        "github_connection_refused_response_limit" => GitHubReason::ResponseLimit,
        _ => GitHubReason::CleanupUnknown,
    }
}
fn provider_error(error: auth_provider::Failure) -> BridgeError {
    github_session::refused(match error {
        auth_provider::Failure::Changed => GitHubReason::TargetChanged,
        auth_provider::Failure::Unavailable => GitHubReason::RuntimeUnavailable,
        // Local gh refusal is not proof of a user cancellation or HTTP 401.
        // A real earlier STOP already remains in the original first-failure.
        auth_provider::Failure::Refused => GitHubReason::InvalidInput,
        auth_provider::Failure::TimedOut => GitHubReason::Expired,
        auth_provider::Failure::Unknown => GitHubReason::CleanupUnknown,
        auth_provider::Failure::InvalidOutput => GitHubReason::ResponseInvalid,
        auth_provider::Failure::OutputLimit => GitHubReason::ResponseLimit,
    })
}
fn source_error(error: Reason) -> BridgeError {
    github_session::refused(match error {
        Reason::CleanupUnknown => GitHubReason::CleanupUnknown,
        Reason::UserCancelled => GitHubReason::Cancelled,
        Reason::SourceChanged | Reason::ContextStale => GitHubReason::TargetChanged,
        _ => GitHubReason::RuntimeUnavailable,
    })
}
fn gui_error(error: Reason) -> BridgeError {
    github_session::refused(match error {
        Reason::CleanupUnknown => GitHubReason::CleanupUnknown,
        Reason::UserCancelled | Reason::Shutdown | Reason::DocumentLost => GitHubReason::Cancelled,
        Reason::Deadline | Reason::ReviewExpired => GitHubReason::Expired,
        Reason::SourceChanged | Reason::ContextStale => GitHubReason::TargetChanged,
        Reason::InvalidRequest | Reason::SourceRefused => GitHubReason::InvalidInput,
        _ => GitHubReason::RuntimeUnavailable,
    })
}

/// Called by the ORIGINAL gui_response under Document, BEFORE it borrows
/// GuiFacts. None means a different purpose; Some(false) is this gh original's
/// refused response, not permission to fall back to another picker owner.
pub(super) fn gui_current_locked(
    document: &DocumentBinding,
    state: &mut DocumentState,
    owner: &Arc<OriginalWork>,
) -> Option<bool> {
    let original = state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .filter(|original| Arc::ptr_eq(&original.original, owner))
        .cloned()?;
    let result = current_locked(document, state, &original, &original.context).and_then(|()| {
        if original
            .facts
            .lock()
            .is_ok_and(|facts| facts.stage == Stage::Picking)
        {
            Ok(())
        } else {
            Err(BridgeError::cleanup_unknown())
        }
    });
    if let Err(error) = &result {
        original.fail(error.clone(), Instant::now());
    }
    Some(result.is_ok())
}
/// This helper does not lock Document or GuiFacts and preserves the original
/// callback's first failure time. It must not manufacture GUI settlement.
pub(super) fn gui_failed_locked(
    state: &DocumentState,
    owner: &Arc<OriginalWork>,
    cause: Reason,
    at: Instant,
) {
    if let Some(original) = state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .filter(|original| Arc::ptr_eq(&original.original, owner))
    {
        original.fail(gui_error(cause), at);
    }
}
fn physical_selection_bounded(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some_and(|text| {
            !text.is_empty()
                && text.len() <= entry_wire::PATH_LIMIT
                && !text.as_bytes().contains(&0)
        })
        && path.file_name().is_some_and(|name| name == "gh")
}
impl Registration {
    fn gate(self: &Arc<Self>) -> GitHubAuthGoGate {
        GitHubAuthGoGate {
            document: self.document.clone(),
            registration: Arc::downgrade(self),
        }
    }
    fn fail(&self, error: BridgeError, at: Instant) {
        {
            let mut facts = self
                .facts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            facts.unknown |= reason(&error) == GitHubReason::CleanupUnknown;
            if facts.failure.as_ref().is_none_or(|(_, first)| at < *first) {
                facts.failure = Some((error, at));
            }
            facts.consent_live = false;
            let end = at
                .min(self.end)
                .checked_add(FAILURE_CLEANUP)
                .unwrap_or(self.end)
                .min(self.end);
            facts.cleanup_end = Some(facts.cleanup_end.map_or(end, |old| old.min(end)));
        }
        self.original.stop();
        // Never lock Provider here: its callbacks take Document. STOP only
        // touches these nonsecret original wait handles in the fixed order.
        if let Ok(active) = self.active.try_lock() {
            if let Some(active) = &*active {
                active.stop();
            }
        }
        if let Ok(http) = self.http.try_lock() {
            if let Some(http) = &*http {
                http.stop();
            }
        }
    }
    fn failure(&self) -> Option<BridgeError> {
        match self.facts.lock() {
            Ok(facts) if facts.unknown => Some(BridgeError::cleanup_unknown()),
            Ok(facts) => facts.failure.as_ref().map(|(error, _)| error.clone()),
            Err(_) => Some(BridgeError::cleanup_unknown()),
        }
    }
    fn cleanup_expired(&self) -> bool {
        let expired = self.facts.lock().map_or(true, |facts| {
            facts.unknown || Instant::now() >= facts.cleanup_end.unwrap_or(self.end)
        });
        if expired {
            self.fail(BridgeError::cleanup_unknown(), Instant::now());
        }
        expired
    }
    fn source_settled(&self) -> bool {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            self.sources
                .try_lock()
                .is_ok_and(|source| source.not_started() || source.settled())
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            false
        }
    }
    fn actual_settled(&self) -> bool {
        let settled = self.original.join_if_ended() == Some(true)
            && self.original.resources_settled()
            && self.source_settled()
            && self.active.try_lock().is_ok_and(|active| active.is_none())
            && self.http.try_lock().is_ok_and(|http| {
                http.as_ref()
                    .is_none_or(|wait| wait.receipt() == GitHubAuthReceipt::Settled)
            })
            && self.facts.try_lock().is_ok_and(|facts| facts.body_returned);
        if settled {
            let Ok(mut facts) = self.facts.try_lock() else {
                return false;
            };
            // Only observing the actual original joins can write this fence.
            // A late observation may permit physical exit, never new success.
            if facts.final_join.is_none() {
                let now = Instant::now();
                facts.final_join = Some(now);
                if now >= facts.cleanup_end.unwrap_or(self.end) {
                    facts.unknown = true;
                }
            }
        }
        settled
    }
    fn custody(&self) -> GitHubAuthCustody {
        if self.facts.try_lock().is_err() {
            return GitHubAuthCustody::Pending;
        }
        let settled = self.actual_settled();
        if self.facts.lock().is_ok_and(|facts| facts.unknown) {
            return GitHubAuthCustody::Unknown;
        }
        if !settled {
            return GitHubAuthCustody::Pending;
        }
        match self.failure() {
            Some(error) => GitHubAuthCustody::Refused(reason(&error)),
            None => GitHubAuthCustody::Ready,
        }
    }
    fn stage(&self, stage: Stage) -> Result<(), BridgeError> {
        let mut facts = self
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if facts.failure.is_some() || facts.unknown || !facts.consent_live {
            return Err(self.failure_unlocked(&facts));
        }
        facts.stage = stage;
        Ok(())
    }
    fn failure_unlocked(&self, facts: &Facts) -> BridgeError {
        if facts.unknown {
            BridgeError::cleanup_unknown()
        } else {
            facts
                .failure
                .as_ref()
                .map_or_else(cancelled, |(error, _)| error.clone())
        }
    }
    fn with_provider<T>(
        &self,
        call: impl FnOnce(&mut NativeGhProvider) -> Result<T, auth_provider::Failure>,
    ) -> Result<T, BridgeError> {
        // ONLY coordinator code calls this, with Document unlocked.
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        call(
            provider
                .as_mut()
                .ok_or(auth_provider::Failure::Unknown)
                .map_err(provider_error)?,
        )
        .map_err(provider_error)
    }
}

/// Nonsecret capability for the SAME original registration. Weak references
/// cannot keep a disappeared Document/registration alive as new authority.
#[derive(Clone)]
pub(crate) struct GitHubAuthGoGate {
    document: Weak<Inner>,
    registration: Weak<Registration>,
}
impl GitHubAuthGoGate {
    fn originals(&self) -> Result<(DocumentBinding, Arc<Registration>), BridgeError> {
        let document = DocumentBinding {
            inner: self.document.upgrade().ok_or_else(cancelled)?,
        };
        let original = self.registration.upgrade().ok_or_else(cancelled)?;
        Ok((document, original))
    }
    pub(crate) fn check_current(&self, context: &wire::Context) -> Result<(), BridgeError> {
        let (document, original) = self.originals()?;
        let mut state = document.lock();
        let result = current_locked(&document, &mut state, &original, context);
        if let Err(error) = &result {
            original.fail(error.clone(), Instant::now());
        }
        result
    }
    pub(crate) fn bind_request(
        &self,
        context: &wire::Context,
        id: &str,
        request: Arc<wire::Request>,
    ) -> Result<(), BridgeError> {
        let (document, original) = self.originals()?;
        let mut state = document.lock();
        current_locked(&document, &mut state, &original, context)?;
        let mut facts = original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let role = &mut facts.roles[role_index(request.role())];
        if !crate::protocol::valid_id(id)
            || role.post != PostState::Inspected
            || role.request.is_some()
            || role.go
        {
            return Err(BridgeError::cleanup_unknown());
        }
        role.request = Some((id.to_owned(), request));
        Ok(())
    }
    pub(crate) fn claim(
        &self,
        id: &str,
        digest: &str,
        context: &wire::Context,
        role: wire::Role,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let (document, original) = self.originals()?;
        let mut state = document.lock();
        current_locked(&document, &mut state, &original, context)?;
        let mut facts = original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let role = &mut facts.roles[role_index(role)];
        let (known_id, request) = role
            .request
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if known_id != id || request.digest() != digest || role.post != PostState::Posted || role.go
        {
            return Err(changed());
        }
        role.go = true; // Spend before the actual original Supervisor claim.
        if !claim() {
            return Err(BridgeError::cleanup_unknown());
        }
        Ok(request.go())
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn source_post(
        &self,
        context: &wire::Context,
        role: wire::Role,
        phase: GitHubAuthSourcePost,
        capture_stopped: &mut dyn FnMut() -> bool,
    ) -> Result<wire::Native, BridgeError> {
        self.check_current(context)?;
        let (_, original) = self.originals()?;
        {
            let mut facts = original
                .facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let expected = if role == wire::Role::Version {
                Stage::Version
            } else {
                Stage::Token
            };
            if facts.stage != expected || !facts.roles[role_index(role)].begin(phase) {
                return Err(BridgeError::cleanup_unknown());
            }
        }
        // No Document mutex survives across native calls. The fixed Supervisor
        // retains this actual worker handle before releasing its entry.
        let result = (|| {
            let mut sources = original
                .sources
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let result = sources.post(&mut || original.original.interrupted() || capture_stopped());
            source_native_failure(&original, sources.first_failure());
            result.map_err(source_error)?;
            let snapshot = sources.native_snapshot().map_err(source_error)?.clone();
            drop(sources);
            let mut facts = original
                .facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if !facts.roles[role_index(role)].returned(phase) {
                return Err(BridgeError::cleanup_unknown());
            }
            Ok(snapshot)
        })();
        if let Err(error) = &result {
            original.fail(error.clone(), Instant::now());
        }
        result
    }
}

fn current_locked(
    document: &DocumentBinding,
    state: &mut DocumentState,
    original: &Arc<Registration>,
    context: &wire::Context,
) -> Result<(), BridgeError> {
    current_checked_locked(document, state, original, context, CheckPurpose::Work)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckPurpose {
    Work,
    Observation,
}
fn work_stage_refused(purpose: CheckPurpose, stage: Stage, body_returned: bool) -> bool {
    purpose == CheckPurpose::Work
        && (body_returned || matches!(stage, Stage::Closing | Stage::BodyReturned))
}
fn current_checked_locked(
    document: &DocumentBinding,
    state: &mut DocumentState,
    original: &Arc<Registration>,
    context: &wire::Context,
    purpose: CheckPurpose,
) -> Result<(), BridgeError> {
    if !state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .is_some_and(|current| Arc::ptr_eq(current, original))
        || !Arc::ptr_eq(&document.inner.session_identity, &original.session_identity)
        || context != &original.context
        || state.session != original.native_session
        || match (&state.context, &original.native_context) {
            (None, None) => false,
            (Some(current), Some(expected)) => !Arc::ptr_eq(current, expected),
            _ => true,
        }
    {
        return Err(changed());
    }
    if let Some(error) = original.failure() {
        return Err(error);
    }
    if !document
        .inner
        .bridge
        .supervisor
        .github_auth_profile_available()
    {
        return Err(github_session::refused(GitHubReason::RuntimeUnavailable));
    }
    let external = document.github_base_gate(state);
    if external != GitHubReason::None {
        return Err(github_session::refused(external));
    }
    if !document.inner.bridge.edits.can_exit() || original.original.stopped() {
        return Err(cancelled());
    }
    if Instant::now() >= original.end {
        return Err(BridgeError::timeout());
    }
    let (generation, root) = document
        .registry_result(
            state,
            document.inner.bridge.native_project(&context.project_id),
            Some(&original.original),
        )
        .map_err(|error| source_error(error.reason))?;
    if generation != context.generation || root != original.root {
        return Err(changed());
    }
    let facts = original
        .facts
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if !facts.consent_live || work_stage_refused(purpose, facts.stage, facts.body_returned) {
        return Err(cancelled());
    }
    if facts.http_started {
        if !state.github.gh_auth_current(&original.original, context) {
            return Err(changed());
        }
    } else if state.github.gh_auth_idle_epoch() != Some(original.idle_connection_epoch) {
        return Err(changed());
    }
    Ok(())
}

/// Connection acceptance observes these facts from the original retained
/// registration; no caller may supply a successful custody boolean/receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHubAuthCustody {
    Pending,
    Ready,
    Refused(GitHubReason),
    Unknown,
}
pub(crate) struct GitHubAuthConnectionHold {
    original: Arc<Registration>,
}
impl GitHubAuthConnectionHold {
    pub(crate) fn custody(&self) -> GitHubAuthCustody {
        self.original.custody()
    }
    pub(crate) fn stop(&self, cause: GitHubReason) {
        self.original
            .fail(github_session::refused(cause), Instant::now());
    }
    pub(crate) fn matches(&self, owner: &Arc<OriginalWork>, context: &wire::Context) -> bool {
        Arc::ptr_eq(owner, &self.original.original) && context == &self.original.context
    }
    pub(crate) fn admitted_target_matches(
        &self,
        project: &str,
        repository: &str,
        generation: u32,
        login: &str,
        revision: &str,
    ) -> bool {
        let context = &self.original.context;
        context.project_id == project
            && context.repository == repository
            && context.generation == generation
            && context.login == login
            && context.revision == revision
            && self.original.facts.lock().is_ok_and(|facts| {
                facts.stage == Stage::Http
                    && facts.http_claimed
                    && !facts.http_started
                    && facts.before_http_returned
                    && facts.consent_live
                    && !facts.unknown
                    && facts.failure.is_none()
            })
    }
}

pub(super) fn pending(state: &DocumentState) -> bool {
    if accounts::pending(state) { return true; }
    state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .is_some_and(|original| {
            matches!(
                original.custody(),
                GitHubAuthCustody::Pending | GitHubAuthCustody::Unknown
            )
        })
}
pub(super) fn can_exit(state: &DocumentState) -> bool {
    if !accounts::can_exit(state) { return false; }
    state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .is_none_or(|original| original.actual_settled())
}
pub(super) fn stop(state: &DocumentState, cause: GitHubReason) {
    accounts::stop(state, cause);
    if let Some(original) = state.gh_auth.as_ref().and_then(Entry::original) {
        if !original.actual_settled() {
            original.fail(github_session::refused(cause), Instant::now());
        }
    }
}
fn observation_scope_only(stage: Stage, body_returned: bool) -> bool {
    body_returned || matches!(stage, Stage::Closing | Stage::BodyReturned)
}
pub(super) fn observe_locked(document: &DocumentBinding, state: &mut DocumentState, now: Instant) {
    accounts::observe(document, state, now);
    let Some(original) = state.gh_auth.as_ref().and_then(Entry::original).cloned() else {
        return;
    };
    if original.original.join_if_ended() == Some(false) {
        original.fail(BridgeError::cleanup_unknown(), now);
    }
    let scope_only = original
        .facts
        .try_lock()
        .is_ok_and(|facts| observation_scope_only(facts.stage, facts.body_returned));
    if !scope_only && original.failure().is_none() {
        // Closing/body return may advance without the Document lock between
        // the sample above and this check. Observation NEVER applies the
        // new-work stage veto; all original target/consent checks still apply.
        if let Err(error) = current_checked_locked(
            document,
            state,
            &original,
            &original.context,
            CheckPurpose::Observation,
        ) {
            original.fail(error, now);
        }
    }
    let failed_expiry = original
        .facts
        .try_lock()
        .is_ok_and(|facts| facts.cleanup_end.is_some_and(|end| now >= end));
    if !original.actual_settled() && (failed_expiry || now >= original.end) {
        original.fail(BridgeError::cleanup_unknown(), now);
    }
    // Closing forbids new GO/consume work, but observing a legitimate close
    // is not cancellation. During/after close, rematch the actual scope under
    // Document BEFORE the same HTTP receipt may pin account/repository.
    if scope_only && original.failure().is_none() {
        let same = state.lifetime.original_bound()
            && !state.lost_observed
            && !state.stopping
            && !state.unknown
            && Arc::ptr_eq(&document.inner.session_identity, &original.session_identity)
            && state.session == original.native_session
            && match (&state.context, &original.native_context) {
                (None, None) => true,
                (Some(current), Some(expected)) => Arc::ptr_eq(current, expected),
                _ => false,
            }
            && original.facts.try_lock().is_ok_and(|facts| {
                if facts.http_started {
                    state
                        .github
                        .gh_auth_current(&original.original, &original.context)
                } else {
                    state.github.gh_auth_idle_epoch() == Some(original.idle_connection_epoch)
                }
            });
        let registry = document.registry_result(
            state,
            document
                .inner
                .bridge
                .native_project(&original.context.project_id),
            Some(&original.original),
        );
        if !same
            || registry.as_ref().is_ok_and(|(generation, root)| {
                *generation != original.context.generation || root != &original.root
            })
        {
            original.fail(changed(), now);
        } else if let Err(error) = registry {
            original.fail(source_error(error.reason), now);
        }
    }
    if original.facts.try_lock().is_ok_and(|facts| facts.unknown) {
        state.unknown = true;
        state.github.unknown();
    }
}

/// Called immediately AFTER the existing connection reconciliation in the
/// same Document lock. Neither body return nor a result-shaped /user message
/// may discard these originals. Unknown originals are never replaced here.
pub(super) fn retire_joined(document: &DocumentBinding, state: &mut DocumentState) {
    accounts::retire(document, state);
    let Some(original) = state.gh_auth.as_ref().and_then(Entry::original).cloned() else {
        return;
    };
    if !matches!(
        original.custody(),
        GitHubAuthCustody::Ready | GitHubAuthCustody::Refused(_)
    ) || state
        .github
        .gh_auth_retains(&original.original, &original.context)
    {
        return;
    }
    let custody = original.custody();
    let snapshot = original_status(document, state, &original);
    let claimed = original
        .facts
        .lock()
        .map_or(true, |facts| facts.http_claimed);
    let handoff_known = original
        .facts
        .lock()
        .is_ok_and(|facts| facts.http_started && facts.http_handoff.is_some());
    if claimed && !handoff_known || !claimed && custody == GitHubAuthCustody::Ready {
        original.fail(BridgeError::cleanup_unknown(), Instant::now());
        state.unknown = true;
        state.github.unknown();
        return;
    }
    let update = original.result.observe(snapshot.clone()).and_then(|()| {
        // A real handoff (possibly already consumed) is immutable in the result
        // slot. Otherwise only positively settled, never-claimed work can say
        // no HTTP. The observer need not be polled before retirement.
        original.result.terminal(no_http_proved(custody, claimed))
    });
    if update.is_err() {
        original.fail(BridgeError::cleanup_unknown(), Instant::now());
        state.unknown = true;
        state.github.unknown();
        return;
    }
    state.gh_auth = Some(Entry::Finished(snapshot));
}
/// No running-owner census is invented. A fresh admission is possible only
/// after the real original has been retired above; otherwise allocation fails.
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    match &state.gh_auth {
        None => Some(0),
        Some(Entry::Original(_)) | Some(Entry::Accounts(_)) => None,
        Some(Entry::AccountsFinished(finished)) => finished.retained_bytes(),
        Some(Entry::Finished(status)) => {
            std::mem::size_of::<Entry>().checked_add(status.retained_bytes()?)
        }
    }
}

impl DocumentBinding {
    pub(crate) fn github_auth_status(&self) -> GitHubAuthStatus {
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        status(self, &state)
    }
    pub(crate) fn github_auth_cancel(
        &self,
        operation_id: &str,
    ) -> Result<GitHubAuthStatus, BridgeError> {
        let mut state = self.lock();
        let original = state
            .gh_auth
            .as_ref()
            .and_then(Entry::original)
            .filter(|original| original.original.id.to_string() == operation_id)
            .ok_or_else(changed)?;
        original.fail(cancelled(), Instant::now());
        self.bump(&mut state);
        Ok(status(self, &state))
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn github_connect_selected_gh(
        &self,
        app: tauri::AppHandle,
        request: GitHubAuthRequest,
    ) -> Result<GitHubAuthConnectObserver, BridgeError> {
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            feature = "desktop-shell",
            feature = "custom-protocol",
            not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher")
        )))]
        {
            let _ = (app, request);
            return Err(github_session::refused(GitHubReason::RuntimeUnavailable));
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
        {
            // No environment lookup, file IO or keyring call before the SAME
            // Document retains the explicit request and its original owner.
            let nomination = crate::github_auth_nomination::StockGhNomination::compiled()
                .ok_or_else(|| github_session::refused(GitHubReason::RuntimeUnavailable))?;
            if !entry_available(self) {
                return Err(github_session::refused(GitHubReason::RuntimeUnavailable));
            }
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            let external = self.github_gate(&state);
            if external != GitHubReason::None {
                return Err(github_session::refused(external));
            }
            if request.expected_document_revision != state.revision
                || request.expected_connection_revision != state.github.snapshot().revision
            {
                return Err(changed());
            }
            if !self.inner.bridge.supervisor.can_exit()
                || !self.inner.bridge.edits.can_exit()
                || state.github.native_work_pending()
                || state.github.registration().is_some()
            {
                return Err(github_session::refused(GitHubReason::Busy));
            }
            if !request.bounded() {
                return Err(BridgeError::invalid());
            }
            let accounts_witness = accounts::selected(self, &mut state, &request)?;
            let idle_connection_epoch = state
                .github
                .gh_auth_idle_epoch()
                .ok_or_else(|| github_session::refused(GitHubReason::Busy))?;
            let (generation, root) = self
                .registry_result(
                    &mut state,
                    self.inner.bridge.native_project(&request.project_id),
                    None,
                )
                .map_err(|error| source_error(error.reason))?;
            let id = self
                .next_operation(&mut state)
                .map_err(|error| source_error(error.reason))?;
            let context = wire::Context {
                project_id: request.project_id.clone(),
                repository: request.repository.clone(),
                login: request.selected_login.clone(),
                generation,
                revision: format!("gh-selection-{id}"),
            };
            if !context.valid() {
                return Err(BridgeError::invalid());
            }
            if state.gh_auth.as_ref().and_then(Entry::original).is_some() {
                return Err(github_session::refused(GitHubReason::Busy));
            }
            // Only bounded finished status may remain. The same census counts
            // it until the actual new registration replaces it below.
            let future = GitHubAuthAdmission::reservation_bytes()
                .and_then(|bytes| bytes.checked_add(asset_source::GhAuthSources::working_bytes()?))
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<OriginalWork>()
                            + std::mem::size_of::<Registration>()
                            + 256 * 1024
                            + entry_wire::ENTRY_BACKING,
                    )
                })
                .ok_or_else(BridgeError::invalid)?;
            lookup_memory::github_auth_admission_bytes(&self.inner, &state, future)
                .map_err(|_| github_session::refused(GitHubReason::Busy))?;
            let end = Instant::now()
                .checked_add(WHOLE)
                .ok_or_else(BridgeError::invalid)?;
            let original = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
            original.set_endpoint(Some(end));
            let result = Arc::new(ResultSlot::new(GitHubAuthStatus {
                schema_version: 1,
                document_revision: state.revision,
                connection_revision: state.github.snapshot().revision,
                available: true,
                operation_id: Some(id.to_string()),
                project_id: Some(context.project_id.clone()),
                repository: Some(context.repository.clone()),
                selected_login: Some(context.login.clone()),
                phase: GitHubAuthPhase::Picking,
                reason: GitHubReason::None,
                http: None,
            }));
            // Observer has no path/source/native owner backreference. It is
            // created before dispatch and cannot become execution authority.
            let observer = GitHubAuthConnectObserver {
                document: Arc::downgrade(&self.inner),
                result: result.clone(),
            };
            let registered = Arc::new(Registration {
                original: original.clone(),
                document: Arc::downgrade(&self.inner),
                session_identity: self.inner.session_identity.clone(),
                native_context: state.context.clone(),
                native_session: state.session,
                idle_connection_epoch,
                root,
                request,
                accounts_witness,
                physical_executable: Mutex::new(None),
                result,
                context,
                end,
                provider: Mutex::new(None),
                active: Mutex::new(None),
                http: Mutex::new(None),
                sources: Mutex::new(asset_source::GhAuthSources::new()),
                nomination,
                facts: Mutex::new(Facts {
                    stage: Stage::Picking,
                    failure: None,
                    cleanup_end: None,
                    unknown: false,
                    consent_live: true,
                    http_claimed: false,
                    http_started: false,
                    http_handoff: None,
                    source_entered: false,
                    source_returned: false,
                    before_http_entered: false,
                    before_http_returned: false,
                    finish_entered: false,
                    close_entered: false,
                    body_returned: false,
                    final_join: None,
                    roles: [RoleBook::new(), RoleBook::new()],
                }),
            });
            let mut coordinator = original
                .coordinator
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            coordinator.receipt = JoinReceipt::Pending;
            state.gh_auth = Some(Entry::Original(registered.clone())); // Retain BEFORE any work/async dispatch.
            let (start, enter) = oneshot::channel();
            let guard = BodyGuard {
                original: registered.clone(),
                _end: CoordinatorEnd(original.clone()),
                normal: false,
            };
            let document = self.clone();
            coordinator.handle = Some(tauri::async_runtime::spawn(async move {
                let mut guard = guard;
                if enter.await.is_err() {
                    // This sole coordinator has not dispatched any GUI call.
                    // It may prove not-created; no ambiguous dispatch is reset.
                    registered.original.gui.not_created(Reason::UserCancelled);
                    registered.fail(BridgeError::cleanup_unknown(), Instant::now());
                } else {
                    coordinate(&document, &registered, app).await;
                }
                if let Ok(mut facts) = registered.facts.lock() {
                    facts.stage = Stage::BodyReturned;
                    facts.body_returned = true;
                }
                guard.normal = true;
            }));
            drop(coordinator);
            if start.send(()).is_err() {
                original.stop();
            }
            self.bump(&mut state);
            Ok(observer)
        }
    }
}
fn entry_available(document: &DocumentBinding) -> bool {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    ))]
    {
        document
            .inner
            .bridge
            .supervisor
            .github_auth_profile_available()
            && document.github_qualified()
            && document.native_qualified()
            && crate::github_auth_nomination::StockGhNomination::compiled().is_some()
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        feature = "desktop-shell",
        feature = "custom-protocol",
        not(feature = "development-runtime"),
        not(feature = "ubuntu-runtime-publisher")
    )))]
    {
        let _ = document;
        false
    }
}
fn status(document: &DocumentBinding, state: &DocumentState) -> GitHubAuthStatus {
    let available = entry_available(document);
    match &state.gh_auth {
        Some(Entry::Original(original)) => {
            let snapshot = original_status(document, state, original);
            let update = original.result.observe(snapshot.clone()).and_then(|()| {
                if snapshot.phase == GitHubAuthPhase::CleanupUnknown {
                    original.result.terminal(false)
                } else {
                    Ok(())
                }
            });
            if update.is_err() {
                original.fail(BridgeError::cleanup_unknown(), Instant::now());
            }
            snapshot
        }
        Some(Entry::Finished(status)) => GitHubAuthStatus {
            available,
            document_revision: state.revision,
            connection_revision: state.github.snapshot().revision,
            ..status.clone()
        },
        None | Some(Entry::Accounts(_)) | Some(Entry::AccountsFinished(_)) => GitHubAuthStatus {
            schema_version: 1,
            document_revision: state.revision,
            connection_revision: state.github.snapshot().revision,
            available,
            operation_id: None,
            project_id: None,
            repository: None,
            phase: GitHubAuthPhase::Idle,
            reason: if available {
                GitHubReason::None
            } else {
                GitHubReason::RuntimeUnavailable
            },
            selected_login: None,
            http: None,
        },
    }
}
fn original_status(
    document: &DocumentBinding,
    state: &DocumentState,
    original: &Registration,
) -> GitHubAuthStatus {
    let available = entry_available(document);
    let custody = original.custody();
    // Brief data-only lock: benign contention must not erase an already
    // retained HTTP identity or turn a progress observation into Unknown.
    let facts = original.facts.lock();
    let (phase, reason) = match custody {
        GitHubAuthCustody::Unknown => (
            GitHubAuthPhase::CleanupUnknown,
            GitHubReason::CleanupUnknown,
        ),
        GitHubAuthCustody::Refused(reason) => (GitHubAuthPhase::Failed, reason),
        // Native custody only. Authentication success remains exclusively the
        // existing ConnectionState /user login + immutable account-ID result.
        GitHubAuthCustody::Ready => (GitHubAuthPhase::Settled, GitHubReason::None),
        GitHubAuthCustody::Pending => facts.as_ref().map_or(
            (GitHubAuthPhase::Stopping, GitHubReason::CleanupUnknown),
            |facts| {
                if let Some((error, _)) = &facts.failure {
                    (GitHubAuthPhase::Stopping, reason(error))
                } else {
                    (
                        if facts.http_started {
                            GitHubAuthPhase::CheckingIdentity
                        } else if facts.stage == Stage::Picking {
                            GitHubAuthPhase::Picking
                        } else {
                            GitHubAuthPhase::Running
                        },
                        GitHubReason::None,
                    )
                }
            },
        ),
    };
    GitHubAuthStatus {
        schema_version: 1,
        document_revision: state.revision,
        connection_revision: state.github.snapshot().revision,
        available,
        operation_id: Some(original.original.id.to_string()),
        project_id: Some(original.context.project_id.clone()),
        repository: Some(original.context.repository.clone()),
        phase,
        reason,
        selected_login: Some(original.context.login.clone()),
        http: facts
            .as_ref()
            .ok()
            .and_then(|facts| facts.http_handoff.clone()),
    }
}

struct BodyGuard {
    original: Arc<Registration>,
    _end: CoordinatorEnd,
    normal: bool,
}
impl Drop for BodyGuard {
    fn drop(&mut self) {
        if !self.normal {
            self.original
                .fail(BridgeError::cleanup_unknown(), Instant::now());
        }
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildStep {
    Inspect,
    BeforeHttp,
    Finish,
    Close,
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) enum ChildCall {
    Connect { original: Arc<Registration>, step: ChildStep },
    Accounts(accounts::ChildCall),
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
impl ChildCall {
    pub(super) fn cleanup(&self) -> bool {
        match self { Self::Connect { step, .. } => *step == ChildStep::Close, Self::Accounts(call) => call.close }
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn source_native_failure(
    original: &Registration,
    first: Option<(
        mrk_macos_installed_native::vault_filesystem::Failure,
        Instant,
    )>,
) {
    use mrk_macos_installed_native::vault_filesystem::Failure;
    if let Some((cause, at)) = first {
        original.fail(
            if cause == Failure::Unknown {
                BridgeError::cleanup_unknown()
            } else if cause == Failure::Stopped {
                cancelled()
            } else {
                github_session::refused(GitHubReason::RuntimeUnavailable)
            },
            at,
        );
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn execute_child(owner: &Arc<OriginalWork>, call: ChildCall) -> Result<(), Reason> {
    let (original, step) = match call {
        ChildCall::Connect { original, step } => (original, step),
        ChildCall::Accounts(call) => return accounts::execute_child(owner, call),
    };
    if !Arc::ptr_eq(owner, &original.original) {
        return Err(Reason::CleanupUnknown);
    }
    let result = (|| {
        {
            let mut facts = original
                .facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let entered = match step {
                ChildStep::Inspect => &mut facts.source_entered,
                ChildStep::BeforeHttp => &mut facts.before_http_entered,
                ChildStep::Finish => &mut facts.finish_entered,
                ChildStep::Close => &mut facts.close_entered,
            };
            if *entered {
                return Err(BridgeError::cleanup_unknown());
            }
            *entered = true;
        }
        if step != ChildStep::Close {
            original.gate().check_current(&original.context)?;
        } else {
            if original.cleanup_expired()
                || original.active.lock().map_or(true, |value| value.is_some())
                || original.http.lock().map_or(true, |value| {
                    value
                        .as_ref()
                        .is_some_and(|wait| wait.receipt() != GitHubAuthReceipt::Settled)
                })
            {
                return Err(BridgeError::cleanup_unknown());
            }
        }
        let mut source = original
            .sources
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let result = match step {
            ChildStep::Inspect => {
                let selected = original
                    .physical_executable
                    .lock()
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let path = selected
                    .as_deref()
                    .ok_or_else(BridgeError::cleanup_unknown)?;
                source.inspect_selected(
                    path,
                    &original.nomination,
                    crate::installed_runtime::GitHubAuthRuntimeSlots::source_runtime_fd_bound(),
                    &mut || owner.interrupted(),
                ).and_then(|()| {
                    let native = source.native_snapshot()?;
                    if original.accounts_witness.as_ref().is_some_and(|w| !w.matches(native, &original.context.login)) {
                        Err(Reason::SourceChanged)
                    } else { Ok(()) }
                })
            }
            ChildStep::BeforeHttp | ChildStep::Finish => source.post(&mut || owner.interrupted()),
            ChildStep::Close => source.close(&mut |first| {
                source_native_failure(&original, first);
                original.cleanup_expired()
            }),
        };
        source_native_failure(&original, source.first_failure());
        result.map_err(source_error)?;
        if step == ChildStep::Close && !source.settled() {
            return Err(BridgeError::cleanup_unknown());
        }
        drop(source);
        let mut facts = original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if step == ChildStep::Inspect {
            facts.source_returned = true;
        }
        if step == ChildStep::BeforeHttp {
            facts.before_http_returned = true;
        }
        Ok(())
    })();
    if let Err(error) = &result {
        original.fail(error.clone(), Instant::now());
    }
    result.map_err(|error| {
        if is_unknown(&error) {
            Reason::CleanupUnknown
        } else {
            Reason::SourceRefused
        }
    })
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn source_call(original: &Arc<Registration>, step: ChildStep) -> Result<(), BridgeError> {
    match child(
        &original.original,
        ChildJob::GitHubAuth(ChildCall::Connect {
            original: original.clone(),
            step,
        }),
    )
    .await
    {
        Ok(ChildEnd::GitHubAuth(Ok(()))) => Ok(()),
        Ok(ChildEnd::GitHubAuth(Err(reason))) | Ok(ChildEnd::Refused(reason)) | Err(reason) => {
            Err(original.failure().unwrap_or_else(|| source_error(reason)))
        }
        _ => Err(BridgeError::cleanup_unknown()),
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn capture(
    document: &DocumentBinding,
    original: &Arc<Registration>,
    role: wire::Role,
) -> Result<(), BridgeError> {
    let admission = GitHubAuthAdmission::reserve(
        original.gate(),
        original.context.clone(),
        role,
        original.end,
    )?;
    let ticket = document
        .inner
        .bridge
        .supervisor
        .start_github_auth(admission)?;
    let wait = Arc::new(ticket.wait_handle());
    *original
        .active
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())? = Some(wait.clone());
    original
        .with_provider(|provider| provider.retain_original(ticket))
        .map(drop)?;
    if wait.returned().await != GitHubAuthReceipt::Settled {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(()) // Provider still owns and must consume this same original ticket.
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell"
))]
async fn pick(
    document: &DocumentBinding,
    original: &Arc<Registration>,
    app: &tauri::AppHandle,
) -> Result<(), BridgeError> {
    if let Err(error) = original.gate().check_current(&original.context) {
        // The sole coordinator has not entered run_owned_dialog. This is the
        // original no-creation path, never a fallback after uncertain dispatch.
        original.original.gui.not_created(Reason::UserCancelled);
        return Err(error);
    }
    let selected = crate::shell::run_owned_dialog(
        app,
        &original.original,
        crate::shell::DialogChoice::GitHubAuthExecutable,
        None,
    )
    .await
    .map_err(gui_error)?;
    let mut state = document.lock();
    let Some(path) = selected else {
        let known_decline = original
            .original
            .gui
            .facts()
            .is_some_and(|facts| project_path_gui_settled(&facts, false));
        return Err(if known_decline {
            cancelled()
        } else {
            BridgeError::cleanup_unknown()
        });
    };
    current_locked(document, &mut state, original, &original.context)?;
    // The panel itself is not authority to execute. Only after its original
    // response/close/release dispatches joined do we retain bounded path DATA;
    // unchanged SourceBook will inspect the physical file and exact nomination.
    if !original
        .original
        .gui
        .facts()
        .is_some_and(|facts| project_path_gui_settled(&facts, true))
    {
        return Err(BridgeError::cleanup_unknown());
    }
    if path.capacity() > entry_wire::PATH_LIMIT || !physical_selection_bounded(&path) {
        return Err(BridgeError::invalid());
    }
    let mut slot = original
        .physical_executable
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?;
    if slot.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    *slot = Some(path);
    original.stage(Stage::Sources)?;
    document.bump(&mut state);
    Ok(())
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell"
))]
async fn run(
    document: &DocumentBinding,
    original: &Arc<Registration>,
    app: &tauri::AppHandle,
) -> Result<(), BridgeError> {
    pick(document, original, app).await?;
    source_call(original, ChildStep::Inspect).await?;
    let provider = NativeGhProvider::registered(original.gate(), original.context.clone())
        .map_err(provider_error)?;
    *original
        .provider
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())? = Some(provider);
    original.stage(Stage::Version)?;
    original.with_provider(NativeGhProvider::arm_version)?;
    capture(document, original, wire::Role::Version).await?;
    let selected = original.with_provider(NativeGhProvider::finish_selection)?;
    original
        .active
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .take();
    original.stage(Stage::Token)?;
    original.with_provider(|provider| provider.arm_token(&selected))?;
    capture(document, original, wire::Role::Token).await?;
    original.stage(Stage::BeforeHttp)?;
    source_call(original, ChildStep::BeforeHttp).await?;
    let prepared = original.with_provider(NativeGhProvider::finish_prepared_connection)?;
    original
        .active
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .take();
    {
        // Prepared token consumption occurred OUTSIDE this mutex. No native
        // callback, process wait or gate re-lock is called by the handoff below.
        let mut state = document.lock();
        current_locked(document, &mut state, original, &original.context)?;
        if Instant::now()
            .checked_add(crate::supervisor::OPERATION_TIME + crate::supervisor::CLEANUP_TIME)
            .is_none_or(|end| end > original.end)
        {
            return Err(BridgeError::timeout());
        }
        {
            let mut facts = original
                .facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if facts.http_claimed
                || !facts.before_http_returned
                || facts
                    .roles
                    .iter()
                    .any(|role| role.post != PostState::Returned || !role.go)
            {
                return Err(BridgeError::cleanup_unknown());
            }
            facts.http_claimed = true;
            facts.stage = Stage::Http;
        }
        // Use the existing HTTP capability state with the SAME base gate;
        // gh-auth's own pending admission must not self-reject as external Busy.
        let external = document.github_base_gate(&state);
        state.github.reconcile(Instant::now(), external);
        let hold = GitHubAuthConnectionHold {
            original: original.clone(),
        };
        let connection = state.github.connect_prepared_gh(
            prepared,
            original.context.project_id.clone(),
            original.context.repository.clone(),
            &original.context.login,
            &original.context.revision,
            original.context.generation,
            hold,
            &document.inner.bridge.supervisor,
            Instant::now(),
            std::time::SystemTime::now(),
        )?;
        let wait = state
            .github
            .gh_auth_wait(&original.original, &original.context)
            .ok_or_else(BridgeError::cleanup_unknown)?;
        *original
            .http
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())? = Some(Arc::new(wait));
        // Save the ACTUAL returned handoff while holding this same Document.
        // A late invoke never rediscovers it from a newer public Connected or
        // depends on the ticket/hold still existing after normal reconciliation.
        let handoff = original.result.handoff(connection)?;
        let mut facts = original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        facts.http_started = true;
        facts.http_handoff = Some(handoff);
        drop(facts);
        document.bump(&mut state);
    }
    let http = original
        .http
        .lock()
        .map_err(|_| BridgeError::cleanup_unknown())?
        .clone()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    if http.returned().await != GitHubAuthReceipt::Settled {
        return Err(BridgeError::cleanup_unknown());
    }
    source_call(original, ChildStep::Finish).await?;
    Ok(())
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    feature = "desktop-shell"
))]
async fn coordinate(
    document: &DocumentBinding,
    original: &Arc<Registration>,
    app: tauri::AppHandle,
) {
    if let Err(error) = run(document, original, &app).await {
        // We do not classify a sent/entered but unconfirmed HTTP call as an
        // unsent retryable selection failure, even if a later child joins.
        let uncertain_claim = original
            .facts
            .lock()
            .map_or(true, |facts| facts.http_claimed && !facts.http_started);
        original.fail(
            if uncertain_claim {
                BridgeError::cleanup_unknown()
            } else {
                error
            },
            Instant::now(),
        );
    }
    if let Some(wait) = original.active.lock().ok().and_then(|slot| slot.clone()) {
        match wait.returned().await {
            GitHubAuthReceipt::Settled | GitHubAuthReceipt::Consumed => {
                let cleaned = original.provider.lock().is_ok_and(|mut provider| {
                    provider
                        .as_mut()
                        .is_some_and(NativeGhProvider::discard_settled_refusal)
                });
                if cleaned {
                    if let Ok(mut active) = original.active.lock() {
                        active.take();
                    }
                } else {
                    original.fail(BridgeError::cleanup_unknown(), Instant::now());
                }
            }
            _ => original.fail(BridgeError::cleanup_unknown(), Instant::now()),
        }
    }
    if let Some(http) = original.http.lock().ok().and_then(|slot| slot.clone()) {
        if http.returned().await != GitHubAuthReceipt::Settled {
            original.fail(BridgeError::cleanup_unknown(), Instant::now());
        }
    }
    if original.failure().as_ref().is_some_and(is_unknown) {
        return;
    }
    if let Ok(mut facts) = original.facts.lock() {
        facts.stage = Stage::Closing;
    }
    if let Err(error) = source_call(original, ChildStep::Close).await {
        original.fail(error, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn pending_gh_picker_excludes_native_peers_before_supervisor_claim_and_keeps_stop_available() {
        // In-memory admission regression. No picker, gh, process, file or
        // native receipt is produced; the unopened bridge only allocates state.
        let bridge = Arc::new(DesktopBridge::new("/unopened-gh-peer-regression".into()));
        let document = DocumentBinding::new(bridge.clone());
        document.hook_installed();
        document.observe(|lifetime| lifetime.started(true));
        document.observe(|lifetime| lifetime.finished(true));
        let context = wire::Context { project_id: "project-1".into(), repository: "fixture/project".into(),
            login: "fixture-user".into(), generation: 1, revision: "gh-selection-1".into() };
        let original = OriginalWork::new(1, true, Arc::downgrade(&document.inner));
        let end = Instant::now() + WHOLE;
        original.set_endpoint(Some(end));
        let initial = GitHubAuthStatus { schema_version: 1, document_revision: 1, connection_revision: 1,
            available: false, operation_id: Some("1".into()), project_id: Some(context.project_id.clone()),
            repository: Some(context.repository.clone()), selected_login: Some(context.login.clone()),
            phase: GitHubAuthPhase::Picking, reason: GitHubReason::None, http: None };
        let registration = Arc::new(Registration {
            original, document: Arc::downgrade(&document.inner), session_identity: document.inner.session_identity.clone(),
            native_context: None, native_session: false, idle_connection_epoch: 1,
            root: asset_source::RegisteredRoot { path: "/unopened-gh-project".into(),
                identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
            request: GitHubAuthRequest { project_id: context.project_id.clone(), repository: context.repository.clone(),
                selected_login: context.login.clone(), expected_document_revision: 1, expected_connection_revision: 1, accounts_observation_id: None },
            accounts_witness: None,
            physical_executable: Mutex::new(None), result: Arc::new(ResultSlot::new(initial)), context, end,
            provider: Mutex::new(None), active: Mutex::new(None), http: Mutex::new(None),
            facts: Mutex::new(Facts { stage: Stage::Picking, failure: None, cleanup_end: None, unknown: false,
                consent_live: true, http_claimed: false, http_started: false, http_handoff: None,
                source_entered: false, source_returned: false, before_http_entered: false, before_http_returned: false,
                finish_entered: false, close_entered: false, body_returned: false, final_join: None,
                roles: [RoleBook::new(), RoleBook::new()] }),
        });
        {
            let mut state = document.lock();
            assert_eq!(document.environment_gate(&state), crate::environment_diagnostics_protocol::Availability::Available);
            state.gh_auth = Some(Entry::Original(registration.clone()));
            assert!(state.slot.is_none() && state.github.registration().is_none() && bridge.supervisor.can_exit());
            assert!(pending(&state));
            assert_eq!(document.environment_gate(&state), crate::environment_diagnostics_protocol::Availability::Busy);
            assert!(passive_document_gate(&state).is_err());
            assert_eq!(status(&document, &state).phase, GitHubAuthPhase::Picking);
        }
        // Cancellation is still accepted. Requesting STOP cannot release the
        // original pending exclusion or manufacture native finality.
        assert!(document.github_auth_cancel("1").is_ok());
        assert!(registration.original.interrupted());
        {
            let state = document.lock();
            assert!(pending(&state));
            assert_eq!(document.environment_gate(&state), crate::environment_diagnostics_protocol::Availability::Busy);
        }
        registration.fail(BridgeError::cleanup_unknown(), Instant::now());
        let state = document.lock();
        assert!(pending(&state));
        assert_eq!(document.environment_gate(&state), crate::environment_diagnostics_protocol::Availability::Busy);
        assert_eq!(status(&document, &state).phase, GitHubAuthPhase::CleanupUnknown);
    }
    #[test]
    fn normal_closing_observation_uses_scope_rematch_without_reopening_work() {
        for stage in [Stage::Closing, Stage::BodyReturned] {
            assert!(observation_scope_only(stage, false));
            assert!(observation_scope_only(stage, true));
            assert!(work_stage_refused(CheckPurpose::Work, stage, false));
            assert!(!work_stage_refused(CheckPurpose::Observation, stage, false));
            assert!(!work_stage_refused(CheckPurpose::Observation, stage, true));
        }
        for stage in [
            Stage::Picking,
            Stage::Sources,
            Stage::Version,
            Stage::Token,
            Stage::BeforeHttp,
            Stage::Http,
        ] {
            assert!(!observation_scope_only(stage, false));
            assert!(!work_stage_refused(CheckPurpose::Work, stage, false));
            assert!(work_stage_refused(CheckPurpose::Work, stage, true));
            // Actual check purpose is fixed even when coordinate advances
            // stage/body-returned after the preliminary observation sample.
            assert!(!work_stage_refused(CheckPurpose::Observation, stage, true));
        }
        // These are the predicates USED by the same original-current helper,
        // not a fake positive native gate or a substitute for actual joins.
    }
    #[test]
    fn fixed_role_post_book_rejects_skips_reentry_and_after_without_go_data_only() {
        let mut book = RoleBook::new();
        assert!(!book.begin(GitHubAuthSourcePost::BeforeGo));
        assert!(!book.begin(GitHubAuthSourcePost::AfterWork));
        assert!(book.begin(GitHubAuthSourcePost::Inspect));
        assert!(!book.begin(GitHubAuthSourcePost::Inspect));
        assert!(!book.returned(GitHubAuthSourcePost::AfterWork));
        assert!(book.returned(GitHubAuthSourcePost::Inspect));
        assert!(!book.begin(GitHubAuthSourcePost::BeforeGo)); // Still lacks the original request.
        assert!(!book.begin(GitHubAuthSourcePost::Inspect));
    }
    #[test]
    fn unknown_and_unrecognized_gate_causes_cannot_become_retryable_source_change() {
        assert_eq!(
            reason(&BridgeError::cleanup_unknown()),
            GitHubReason::CleanupUnknown
        );
        assert_eq!(
            reason(&github_session::refused(GitHubReason::CleanupUnknown)),
            GitHubReason::CleanupUnknown
        );
        assert_eq!(
            reason(&BridgeError::new("unrecognized", "fixed")),
            GitHubReason::CleanupUnknown
        );
        assert_eq!(reason(&changed()), GitHubReason::TargetChanged);
    }
    #[test]
    fn default_gate_data_cannot_mint_original_document_or_gh_nomination() {
        let gate = GitHubAuthGoGate {
            document: Weak::new(),
            registration: Weak::new(),
        };
        let context = wire::Context {
            login: "fixture-user".into(),
            project_id: "fixture-project".into(),
            repository: "fixture-owner/fixture-repo".into(),
            generation: 1,
            revision: "fixture-revision".into(),
        };
        assert!(gate.check_current(&context).is_err());
        let claimed = std::cell::Cell::new(false);
        assert!(gate
            .claim(
                "fixture-operation",
                &"a".repeat(64),
                &context,
                wire::Role::Token,
                || {
                    claimed.set(true);
                    true
                }
            )
            .is_err());
        assert!(!claimed.get());
    }
    #[test]
    fn request_capacity_and_coordinates_are_checked_before_clone_or_native_work() {
        let mut request = GitHubAuthRequest {
            project_id: "fixture-project".into(),
            repository: "fixture-owner/fixture-repo".into(),
            selected_login: "fixture-login".into(),
            expected_document_revision: 1,
            expected_connection_revision: 1,
            accounts_observation_id: None,
        };
        assert!(request.bounded());
        request.selected_login = String::with_capacity(16385);
        request.selected_login.push('a');
        assert!(!request.bounded());
        request.selected_login = "fixture-login".into();
        request.repository = "fixture-owner/fixture-repo?redirect=1".into();
        assert!(!request.bounded());
    }
    fn auth_data() -> GitHubAuthStatus {
        GitHubAuthStatus {
            schema_version: 1,
            document_revision: 4,
            connection_revision: 2,
            available: false,
            operation_id: Some("fixture-gh-operation".into()),
            project_id: Some("fixture-project".into()),
            repository: Some("fixture-owner/fixture-repo".into()),
            selected_login: Some("fixture-login".into()),
            phase: GitHubAuthPhase::Picking,
            reason: GitHubReason::None,
            http: None,
        }
    }
    fn handoff_data() -> crate::github_connection_protocol::Status {
        // Deliberately only DATA. No private ConnectionState session/ticket,
        // nominated executable, GUI, native receipt or Connected proof exists.
        use crate::github_connection_protocol::{
            Operation, OperationKind, Phase, Session, SessionState,
        };
        let mut status = ConnectionState::new().snapshot();
        status.capability.read_only_session_available = true;
        status.capability.reason = GitHubReason::None;
        status.session = Some(Session {
            id: "fixture-http-session".into(),
            project_id: "fixture-project".into(),
            target_repository: "fixture-owner/fixture-repo".into(),
            state: SessionState::Checking,
            expires_at: Some("2026-10-19T12:00:00Z".into()),
        });
        status.operation = Some(Operation {
            id: "fixture-http-operation".into(),
            kind: OperationKind::Connect,
            phase: Phase::Running,
            reason: GitHubReason::None,
        });
        assert!(crate::github_connection_protocol::decode_status(
            &serde_json::to_vec(&status).unwrap()
        )
        .is_ok());
        status
    }
    #[test]
    fn terminal_no_http_requires_original_known_refusal_and_no_claim_data_only() {
        for custody in [
            GitHubAuthCustody::Pending,
            GitHubAuthCustody::Ready,
            GitHubAuthCustody::Unknown,
            GitHubAuthCustody::Refused(GitHubReason::None),
            GitHubAuthCustody::Refused(GitHubReason::CleanupUnknown),
        ] {
            assert!(!no_http_proved(custody, false));
            assert!(!no_http_proved(custody, true));
        }
        assert!(no_http_proved(
            GitHubAuthCustody::Refused(GitHubReason::Cancelled),
            false
        ));
        assert!(!no_http_proved(
            GitHubAuthCustody::Refused(GitHubReason::Cancelled),
            true
        ));
        let mut status = auth_data();
        status.phase = GitHubAuthPhase::Failed;
        status.reason = GitHubReason::Cancelled;
        let slot = ResultSlot::new(status);
        slot.terminal(true).unwrap();
        assert!(matches!(
            slot.take().unwrap().unwrap().outcome,
            entry_wire::Outcome::NoHttp { .. }
        ));
        assert!(slot.take().is_err());
    }
    #[test]
    fn late_observer_gets_exact_original_handoff_once_not_a_newer_connection() {
        let slot = ResultSlot::new(auth_data());
        let original = handoff_data();
        let handoff = slot.handoff(original.clone()).unwrap();
        let mut later = auth_data();
        later.http = Some(handoff);
        later.phase = GitHubAuthPhase::Settled;
        later.connection_revision = 999;
        slot.observe(later).unwrap();
        // Normal hold/ticket retirement cannot overwrite an already latched
        // historical handoff, even when no invoke observer polled until now.
        slot.terminal(false).unwrap();
        let result = slot.take().unwrap().unwrap();
        let entry_wire::Outcome::HttpHandoff { connection } = result.outcome else {
            panic!("lost original handoff DATA")
        };
        assert_eq!(connection, original);
        assert_ne!(connection.revision, 999);
        assert!(slot.handoff(handoff_data()).is_err());
        assert!(slot.take().is_err());
    }
    #[test]
    fn handoff_data_rejects_cross_target_and_non_connect_status_without_authority() {
        for field in 0..4 {
            let slot = ResultSlot::new(auth_data());
            let mut status = handoff_data();
            match field {
                0 => status.session.as_mut().unwrap().project_id = "foreign-project".into(),
                1 => {
                    status.session.as_mut().unwrap().target_repository =
                        "other-owner/other-repo".into()
                }
                2 => {
                    status.operation.as_mut().unwrap().kind =
                        crate::github_connection_protocol::OperationKind::Refresh
                }
                _ => {
                    status.session.as_mut().unwrap().state =
                        crate::github_connection_protocol::SessionState::Connected
                }
            }
            assert!(slot.handoff(status).is_err());
            slot.terminal(false).unwrap();
            assert!(matches!(
                slot.take().unwrap().unwrap().outcome,
                entry_wire::Outcome::Unknown { .. }
            ));
        }
    }
    #[tokio::test]
    async fn lost_document_observer_is_unknown_not_no_http_or_native_retention() {
        let result = Arc::new(ResultSlot::new(auth_data()));
        let observer = GitHubAuthConnectObserver {
            document: Weak::new(),
            result: result.clone(),
        };
        let reply = observer.returned().await.unwrap();
        assert!(matches!(reply.outcome, entry_wire::Outcome::Unknown { .. }));
        assert_eq!(Arc::strong_count(&result), 1);
        assert!(result.take().is_err());
    }
    #[test]
    fn dropped_observer_does_not_hold_original_work_or_runtime_backing() {
        // Empty original allocation only, no native resource work/qualification.
        let original = OriginalWork::new(1, false, Weak::new());
        let weak = Arc::downgrade(&original);
        let data = Arc::new(ResultSlot::new(auth_data()));
        let observer = GitHubAuthConnectObserver {
            document: Weak::new(),
            result: data.clone(),
        };
        drop(original);
        assert!(weak.upgrade().is_none()); // DATA observer has no original edge.
        drop(observer);
        assert_eq!(Arc::strong_count(&data), 1);
    }
    #[test]
    fn physical_selection_is_only_bounded_path_data_not_execution_authority() {
        assert!(physical_selection_bounded(std::path::Path::new(
            "/fixture/installed/gh"
        )));
        for path in ["gh", "/fixture/not-gh", "/fixture/gh\0", ""] {
            assert!(!physical_selection_bounded(std::path::Path::new(path)));
        }
        assert!(!physical_selection_bounded(std::path::Path::new(&format!(
            "/{}/gh",
            "a".repeat(4096)
        ))));
    }
    #[test]
    fn gh_uses_original_gui_receipt_predicate_not_response_or_path_alone() {
        let facts = || GuiFacts {
            dispatched: true,
            constructing: false,
            created: true,
            showing: false,
            response: true,
            accepted: true,
            declined: false,
            accepted_at: Some(Instant::now()),
            destroyed: true,
            released: true,
            not_created: false,
            close_queued: true,
            close_ack: true,
            release_queued: true,
            selected: None,
            refusal: None,
        };
        // Scalar predicate fixture, not a successful native panel/owner proof.
        assert!(project_path_gui_settled(&facts(), true));
        for field in 0..9 {
            let mut value = facts();
            match field {
                0 => value.dispatched = false,
                1 => value.constructing = true,
                2 => value.showing = true,
                3 => value.destroyed = false,
                4 => value.close_ack = false,
                5 => value.released = false,
                6 => value.selected = Some("/fixture/gh".into()),
                7 => value.refusal = Some(Reason::CleanupUnknown),
                _ => value.accepted_at = None,
            }
            assert!(!project_path_gui_settled(&value, true));
        }
    }
    #[test]
    fn gui_error_preserves_native_stop_deadline_and_unknown_classification() {
        assert_eq!(
            reason(&gui_error(Reason::CleanupUnknown)),
            GitHubReason::CleanupUnknown
        );
        assert_eq!(
            reason(&gui_error(Reason::UserCancelled)),
            GitHubReason::Cancelled
        );
        assert_eq!(reason(&gui_error(Reason::Deadline)), GitHubReason::Expired);
        assert_eq!(
            reason(&gui_error(Reason::SourceChanged)),
            GitHubReason::TargetChanged
        );
    }
}
