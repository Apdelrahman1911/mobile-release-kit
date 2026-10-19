//! Selected official gh under the SAME actual Document and OriginalWork.
//! There is no renderer credential, alternate command executor, service DTO
//! admission, PATH discovery, or substitute History provider. This entry stays
//! unavailable without the distinct installed stock nomination/profile.
use super::*;
use crate::{
    github_auth_capture_wire as wire,
    github_auth_native_owner::NativeGhProvider,
    github_connection_session::auth_provider,
    supervisor::{
        GitHubAuthAdmission, GitHubAuthHttpWait, GitHubAuthReceipt, GitHubAuthSourcePost,
        GitHubAuthWait,
    },
};
use std::path::PathBuf;

const WHOLE: Duration = Duration::from_secs(60);
const FAILURE_CLEANUP: Duration = Duration::from_secs(10);

/// Native command DATA. Only `DocumentBinding::github_connect_selected_gh`
/// can retain it with the original session/registry and mint its one-use gate.
/// A future native picker may supply the physical path; it never supplies a
/// hash/nomination or authority to execute a different version of that file.
pub(crate) struct GitHubAuthRequest {
    pub(crate) project_id: String,
    pub(crate) repository: String,
    pub(crate) selected_login: String,
    pub(crate) physical_executable: PathBuf,
    pub(crate) expected_document_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
impl GitHubAuthRequest {
    fn bounded(&self) -> bool {
        self.project_id
            .capacity()
            .checked_add(self.repository.capacity())
            .and_then(|bytes| bytes.checked_add(self.selected_login.capacity()))
            .and_then(|bytes| bytes.checked_add(self.physical_executable.capacity()))
            .is_some_and(|bytes| bytes <= 16384)
            && self.selected_login.len() <= 39
            && crate::protocol::valid_id(&self.project_id)
            && crate::github_connection_protocol::coordinate(&self.repository)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitHubAuthPhase {
    Idle,
    Running,
    CheckingIdentity,
    Settled,
    Failed,
    CleanupUnknown,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitHubAuthStatus {
    available: bool,
    operation_id: Option<String>,
    phase: GitHubAuthPhase,
    reason: GitHubReason,
    // Selection remains unverified until the ORIGINAL HTTP /user checks it.
    selected_login: Option<String>,
}
// Only a positively joined original may be replaced by this bounded public
// history. Keeping the whole retired Supervisor here would also keep its
// closed runtime inventory allocation alive during a later operation.
pub(super) enum Entry {
    Original(Arc<Registration>),
    Finished(GitHubAuthStatus),
}
impl Entry {
    fn original(&self) -> Option<&Arc<Registration>> {
        match self {
            Self::Original(original) => Some(original),
            Self::Finished(_) => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
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
    state
        .gh_auth
        .as_ref()
        .and_then(Entry::original)
        .is_none_or(|original| original.actual_settled())
}
pub(super) fn stop(state: &DocumentState, cause: GitHubReason) {
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
    let snapshot = original_status(document, &original);
    state.gh_auth = Some(Entry::Finished(snapshot));
}
/// No running-owner census is invented. A fresh admission is possible only
/// after the real original has been retired above; otherwise allocation fails.
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    match &state.gh_auth {
        None => Some(0),
        Some(Entry::Original(_)) => None,
        Some(Entry::Finished(status)) => std::mem::size_of::<Entry>()
            .checked_add(status.operation_id.as_ref().map_or(0, String::capacity))?
            .checked_add(status.selected_login.as_ref().map_or(0, String::capacity)),
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
    pub(crate) fn github_connect_selected_gh(
        &self,
        request: GitHubAuthRequest,
    ) -> Result<GitHubAuthStatus, BridgeError> {
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
            let _ = request;
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
            if !self.inner.bridge.supervisor.github_auth_profile_available() {
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
            let idle_connection_epoch = state
                .github
                .gh_auth_idle_epoch()
                .ok_or_else(|| github_session::refused(GitHubReason::Busy))?;
            let path = request
                .physical_executable
                .to_str()
                .ok_or_else(BridgeError::invalid)?;
            if path.is_empty()
                || path.len() > 4096
                || !request.physical_executable.is_absolute()
                || request
                    .physical_executable
                    .file_name()
                    .is_none_or(|name| name != "gh")
            {
                return Err(BridgeError::invalid());
            }
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
                            + 256 * 1024,
                    )
                })
                .ok_or_else(BridgeError::invalid)?;
            lookup_memory::github_auth_admission_bytes(&self.inner, &state, future)
                .map_err(|_| github_session::refused(GitHubReason::Busy))?;
            let end = Instant::now()
                .checked_add(WHOLE)
                .ok_or_else(BridgeError::invalid)?;
            let original = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
            original.set_endpoint(Some(end));
            let registered = Arc::new(Registration {
                original: original.clone(),
                document: Arc::downgrade(&self.inner),
                session_identity: self.inner.session_identity.clone(),
                native_context: state.context.clone(),
                native_session: state.session,
                idle_connection_epoch,
                root,
                request,
                context,
                end,
                provider: Mutex::new(None),
                active: Mutex::new(None),
                http: Mutex::new(None),
                sources: Mutex::new(asset_source::GhAuthSources::new()),
                nomination,
                facts: Mutex::new(Facts {
                    stage: Stage::Sources,
                    failure: None,
                    cleanup_end: None,
                    unknown: false,
                    consent_live: true,
                    http_claimed: false,
                    http_started: false,
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
                    registered.fail(BridgeError::cleanup_unknown(), Instant::now());
                } else {
                    coordinate(&document, &registered).await;
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
            Ok(status(self, &state))
        }
    }
}
fn status(document: &DocumentBinding, state: &DocumentState) -> GitHubAuthStatus {
    let available = document
        .inner
        .bridge
        .supervisor
        .github_auth_profile_available()
        && document.github_qualified();
    match &state.gh_auth {
        Some(Entry::Original(original)) => original_status(document, original),
        Some(Entry::Finished(status)) => GitHubAuthStatus {
            available,
            ..status.clone()
        },
        None => GitHubAuthStatus {
            available,
            operation_id: None,
            phase: GitHubAuthPhase::Idle,
            reason: if available {
                GitHubReason::None
            } else {
                GitHubReason::RuntimeUnavailable
            },
            selected_login: None,
        },
    }
}
fn original_status(document: &DocumentBinding, original: &Registration) -> GitHubAuthStatus {
    let available = document
        .inner
        .bridge
        .supervisor
        .github_auth_profile_available()
        && document.github_qualified();
    let (phase, reason) = match original.custody() {
        GitHubAuthCustody::Unknown => (
            GitHubAuthPhase::CleanupUnknown,
            GitHubReason::CleanupUnknown,
        ),
        GitHubAuthCustody::Refused(reason) => (GitHubAuthPhase::Failed, reason),
        // Native custody only. Authentication success remains exclusively the
        // existing ConnectionState /user login + immutable account-ID result.
        GitHubAuthCustody::Ready => (GitHubAuthPhase::Settled, GitHubReason::None),
        GitHubAuthCustody::Pending => (
            if original
                .facts
                .try_lock()
                .is_ok_and(|facts| facts.http_started)
            {
                GitHubAuthPhase::CheckingIdentity
            } else {
                GitHubAuthPhase::Running
            },
            GitHubReason::None,
        ),
    };
    GitHubAuthStatus {
        available,
        operation_id: Some(original.original.id.to_string()),
        phase,
        reason,
        selected_login: Some(original.context.login.clone()),
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
pub(super) struct ChildCall {
    original: Arc<Registration>,
    step: ChildStep,
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
impl ChildCall {
    pub(super) fn cleanup(&self) -> bool {
        self.step == ChildStep::Close
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
    let original = call.original;
    if !Arc::ptr_eq(owner, &original.original) {
        return Err(Reason::CleanupUnknown);
    }
    let result = (|| {
        {
            let mut facts = original
                .facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let entered = match call.step {
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
        if call.step != ChildStep::Close {
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
        let result = match call.step {
            ChildStep::Inspect => source.inspect_selected(
                &original.request.physical_executable,
                &original.nomination,
                crate::installed_runtime::GitHubAuthRuntimeSlots::source_runtime_fd_bound(),
                &mut || owner.interrupted(),
            ),
            ChildStep::BeforeHttp | ChildStep::Finish => source.post(&mut || owner.interrupted()),
            ChildStep::Close => source.close(&mut |first| {
                source_native_failure(&original, first);
                original.cleanup_expired()
            }),
        };
        source_native_failure(&original, source.first_failure());
        result.map_err(source_error)?;
        if call.step == ChildStep::Close && !source.settled() {
            return Err(BridgeError::cleanup_unknown());
        }
        drop(source);
        let mut facts = original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if call.step == ChildStep::Inspect {
            facts.source_returned = true;
        }
        if call.step == ChildStep::BeforeHttp {
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
        ChildJob::GitHubAuth(ChildCall {
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
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn run(document: &DocumentBinding, original: &Arc<Registration>) -> Result<(), BridgeError> {
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
        state.github.connect_prepared_gh(
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
        original
            .facts
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .http_started = true;
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
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn coordinate(document: &DocumentBinding, original: &Arc<Registration>) {
    if let Err(error) = run(document, original).await {
        original.fail(error, Instant::now());
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
            physical_executable: "/fixture/official/gh".into(),
            expected_document_revision: 1,
            expected_connection_revision: 1,
        };
        assert!(request.bounded());
        request.selected_login = String::with_capacity(16385);
        request.selected_login.push('a');
        assert!(!request.bounded());
        request.selected_login = "fixture-login".into();
        request.repository = "fixture-owner/fixture-repo?redirect=1".into();
        assert!(!request.bounded());
    }
}
