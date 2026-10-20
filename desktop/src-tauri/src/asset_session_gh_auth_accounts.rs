//! Config-only variant in the SAME gh Entry, OriginalWork and ChildJob slots.
//! No process/HTTP/keyring/picker is entered; no second registry or executor.
//! Original SourceBook/ACL close and coordinator joins precede usable names.
use super::*;
use crate::github_auth_accounts as accounts_wire;

struct Facts {
    entered: bool,
    closed: bool,
    body_returned: bool,
    final_join: Option<Instant>,
    failure: Option<(BridgeError, Instant)>,
    cleanup_end: Option<Instant>,
    unknown: bool,
    witness: Option<accounts_wire::Witness>,
}
pub(super) struct Read {
    original: Arc<OriginalWork>,
    document: Weak<Inner>,
    session_identity: Arc<()>,
    native_context: Option<Arc<NativeContext>>,
    native_session: bool,
    idle_epoch: u32,
    document_revision: u32,
    generation: u32,
    root: asset_source::RegisteredRoot,
    request: accounts_wire::Request,
    end: Instant,
    facts: Mutex<Facts>,
    result: Arc<Mutex<Option<accounts_wire::Status>>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    sources: Mutex<asset_source::GhAuthSources>,
}
pub(super) struct Finished {
    status: accounts_wire::Status,
    witness: Option<accounts_wire::Witness>,
    session_identity: Weak<()>,
    native_context: Option<Weak<NativeContext>>,
    native_session: bool,
    idle_epoch: u32,
    generation: u32,
    root: asset_source::RegisteredRoot,
}
impl Read {
    fn fail(&self, error: BridgeError, now: Instant) {
        let mut f = match self.facts.lock() {
            Ok(f) => f,
            Err(p) => {
                let mut f = p.into_inner();
                f.unknown = true;
                f
            }
        };
        f.unknown |= is_unknown(&error);
        if f.failure.as_ref().is_none_or(|(_, old)| now < *old) {
            f.failure = Some((error, now));
        }
        let end = now
            .min(self.end)
            .checked_add(FAILURE_CLEANUP)
            .unwrap_or(self.end)
            .min(self.end);
        f.cleanup_end = Some(f.cleanup_end.map_or(end, |old| old.min(end)));
        drop(f);
        self.original.stop();
    }
    fn failure(&self) -> Option<BridgeError> {
        self.facts
            .lock()
            .map_or(Some(BridgeError::cleanup_unknown()), |f| {
                if f.unknown {
                    Some(BridgeError::cleanup_unknown())
                } else {
                    f.failure.as_ref().map(|(e, _)| e.clone())
                }
            })
    }
    fn cleanup_expired(&self) -> bool {
        self.facts.lock().map_or(true, |f| {
            f.unknown || Instant::now() >= f.cleanup_end.unwrap_or(self.end)
        })
    }
    pub(super) fn settled(&self) -> bool {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        let sources = self
            .sources
            .try_lock()
            .is_ok_and(|s| s.not_started() || s.settled());
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        let sources = false;
        if self.original.join_if_ended() != Some(true)
            || !self.original.resources_settled()
            || !sources
        {
            return false;
        }
        let Ok(mut f) = self.facts.try_lock() else {
            return false;
        };
        if !f.body_returned {
            return false;
        }
        if f.final_join.is_none() {
            let now = Instant::now();
            f.final_join = Some(now);
            if now >= f.cleanup_end.unwrap_or(self.end) {
                f.unknown = true;
            }
        }
        true
    }
    fn status(&self, document: &DocumentBinding, state: &DocumentState) -> accounts_wire::Status {
        let settled = self.settled();
        let (phase, reason) = self.facts.lock().map_or(
            (
                accounts_wire::Phase::CleanupUnknown,
                GitHubReason::CleanupUnknown,
            ),
            |f| {
                if f.unknown {
                    (
                        accounts_wire::Phase::CleanupUnknown,
                        GitHubReason::CleanupUnknown,
                    )
                } else if let Some((error, _)) = &f.failure {
                    (
                        if settled {
                            accounts_wire::Phase::Failed
                        } else {
                            accounts_wire::Phase::Stopping
                        },
                        reason(error),
                    )
                } else {
                    // Usable success is published only by retire() with the
                    // complete witness, after the original join/close checks.
                    (accounts_wire::Phase::Reading, GitHubReason::None)
                }
            },
        );
        accounts_wire::Status {
            schema_version: 1,
            kind: "accounts",
            document_revision: state.revision,
            connection_revision: state.github.snapshot().revision,
            available: entry_available(document),
            operation_id: self.original.id.to_string(),
            project_id: self.request.project_id.clone(),
            repository: self.request.repository.clone(),
            phase,
            reason,
            accounts: None,
        }
    }
}
fn original(state: &DocumentState) -> Option<&Arc<Read>> {
    match &state.gh_auth {
        Some(Entry::Accounts(read)) => Some(read),
        _ => None,
    }
}
pub(super) fn active(state: &DocumentState) -> bool {
    original(state).is_some()
}
pub(super) fn pending(state: &DocumentState) -> bool {
    original(state).is_some_and(|r| !r.settled() || r.failure().as_ref().is_some_and(is_unknown))
}
pub(super) fn can_exit(state: &DocumentState) -> bool {
    original(state).is_none_or(|r| r.settled())
}
pub(super) fn stop(state: &DocumentState, cause: GitHubReason) {
    if let Some(read) = original(state) {
        if !read.settled() {
            read.fail(github_session::refused(cause), Instant::now());
        }
    }
}
fn scope_current(
    document: &DocumentBinding,
    state: &mut DocumentState,
    read: &Arc<Read>,
) -> Result<(), BridgeError> {
    if !original(state).is_some_and(|r| Arc::ptr_eq(r, read))
        || !Arc::ptr_eq(&document.inner.session_identity, &read.session_identity)
        || state.session != read.native_session
        || state.revision != read.document_revision
        || match (&state.context, &read.native_context) {
            (None, None) => false,
            (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
            _ => true,
        }
        || state.github.gh_auth_idle_epoch() != Some(read.idle_epoch)
    {
        return Err(changed());
    }
    let gate = document.github_base_gate(state);
    if gate != GitHubReason::None {
        return Err(github_session::refused(gate));
    }
    let (generation, root) = document
        .registry_result(
            state,
            document
                .inner
                .bridge
                .native_project(&read.request.project_id),
            Some(&read.original),
        )
        .map_err(|e| source_error(e.reason))?;
    if generation != read.generation || root != read.root {
        return Err(changed());
    }
    Ok(())
}
fn current(
    document: &DocumentBinding,
    state: &mut DocumentState,
    read: &Arc<Read>,
) -> Result<(), BridgeError> {
    scope_current(document, state, read)?;
    if let Some(error) = read.failure() {
        return Err(error);
    }
    if read.original.stopped() || !entry_available(document) {
        return Err(cancelled());
    }
    if Instant::now() >= read.end {
        return Err(BridgeError::timeout());
    }
    Ok(())
}
pub(super) fn observe(document: &DocumentBinding, state: &mut DocumentState, now: Instant) {
    let Some(read) = original(state).cloned() else {
        return;
    };
    if read.original.join_if_ended() == Some(false) {
        read.fail(BridgeError::cleanup_unknown(), now);
    }
    if read.failure().is_none() {
        if let Err(error) = scope_current(document, state, &read) {
            read.fail(error, now);
        }
    }
    if !read.settled()
        && read
            .facts
            .lock()
            .map_or(true, |f| now >= f.cleanup_end.unwrap_or(read.end))
    {
        read.fail(BridgeError::cleanup_unknown(), now);
    }
    if read.failure().as_ref().is_some_and(is_unknown) {
        state.unknown = true;
        state.github.unknown();
        if let Ok(mut result) = read.result.try_lock() {
            result.get_or_insert_with(|| read.status(document, state));
        }
    }
}
pub(super) fn retire(document: &DocumentBinding, state: &mut DocumentState) {
    let Some(read) = original(state).cloned() else {
        return;
    };
    if !read.settled() || read.failure().as_ref().is_some_and(is_unknown) {
        return;
    }
    // The returning observer briefly owns this same DATA cell. Reserve it
    // before consuming the witness; ordinary contention defers retirement,
    // not the original source read/close and never its known finality.
    let mut result = match read.result.try_lock() {
        Ok(result) => result,
        Err(std::sync::TryLockError::WouldBlock) => return,
        Err(std::sync::TryLockError::Poisoned(_)) => {
            read.fail(BridgeError::cleanup_unknown(), Instant::now());
            state.unknown = true;
            return;
        }
    };
    let mut status = read.status(document, state);
    let Ok(mut f) = read.facts.try_lock() else {
        return;
    };
    let witness = if f.failure.is_none() {
        f.witness.take()
    } else {
        None
    };
    if f.failure.is_none() && witness.is_none() {
        drop(f);
        read.fail(BridgeError::cleanup_unknown(), Instant::now());
        state.unknown = true;
        return;
    }
    if let Some(w) = &witness {
        status.phase = accounts_wire::Phase::Settled;
        status.accounts = Some(accounts_wire::List {
            observation_id: format!("gh-accounts-{}", read.original.id),
            logins: w.logins.clone(),
            current: true,
        });
    }
    drop(f);
    let finished = Finished {
        status: status.clone(),
        witness,
        session_identity: Arc::downgrade(&read.session_identity),
        native_context: read.native_context.as_ref().map(Arc::downgrade),
        native_session: read.native_session,
        idle_epoch: read.idle_epoch,
        generation: read.generation,
        root: read.root.clone(),
    };
    if finished
        .retained_bytes()
        .is_none_or(|n| n > entry_wire::ENTRY_BACKING)
    {
        read.fail(BridgeError::cleanup_unknown(), Instant::now());
        state.unknown = true;
        return;
    }
    if result.is_none() {
        *result = Some(status);
    }
    state.gh_auth = Some(Entry::AccountsFinished(finished));
}
impl Finished {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.status
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(self.root.path.capacity())?
            .checked_add(
                self.witness
                    .as_ref()
                    .map_or(Some(0), accounts_wire::Witness::retained_bytes)?,
            )?
            .checked_add(std::mem::size_of::<NativeContext>() + 128)
    }
    fn current(&self, document: &DocumentBinding, state: &DocumentState) -> bool {
        self.witness.is_some()
            && self.status.document_revision == state.revision
            && self.status.connection_revision == state.github.snapshot().revision
            && self
                .session_identity
                .upgrade()
                .is_some_and(|s| Arc::ptr_eq(&s, &document.inner.session_identity))
            && self.native_session == state.session
            && (match (&self.native_context, &state.context) {
                (None, None) => true,
                (Some(a), Some(b)) => a.upgrade().is_some_and(|a| Arc::ptr_eq(&a, b)),
                _ => false,
            })
            && state.github.gh_auth_idle_epoch() == Some(self.idle_epoch)
            && state.lifetime.original_bound()
            && !state.lost_observed
            && !state.unknown
            && !state.stopping
            && !state.retiring
            && !state.quit_pending
    }
}
pub(super) fn status(
    document: &DocumentBinding,
    state: &DocumentState,
) -> Option<accounts_wire::Status> {
    match &state.gh_auth {
        Some(Entry::Accounts(read)) => Some(read.status(document, state)),
        Some(Entry::AccountsFinished(f)) => {
            let mut status = f.status.clone();
            status.available = entry_available(document);
            status.document_revision = state.revision;
            status.connection_revision = state.github.snapshot().revision;
            if let Some(list) = &mut status.accounts {
                list.current = f.current(document, state);
            }
            Some(status)
        }
        _ => None,
    }
}
pub(super) fn cancel(
    document: &DocumentBinding,
    state: &mut DocumentState,
    id: &str,
) -> Option<Result<accounts_wire::Status, BridgeError>> {
    // A Stop may arrive after the same original has joined. Returning its
    // retained terminal DATA is not a new cancellation or a fabricated receipt.
    if let Some(Entry::AccountsFinished(finished)) = &state.gh_auth {
        return Some(if finished.status.operation_id == id {
            status(document, state).ok_or_else(BridgeError::cleanup_unknown)
        } else {
            Err(changed())
        });
    }
    let read = original(state)?;
    if read.original.id.to_string() != id {
        return Some(Err(changed()));
    }
    read.fail(cancelled(), Instant::now());
    document.bump(state);
    Some(status(document, state).ok_or_else(BridgeError::cleanup_unknown))
}
/// Called BEFORE new Connect admission replaces Entry. The returned private
/// witness is DATA to recheck against its NEW held source, not an executable or
/// credential lease. No caller id, revision or listed name creates it.
pub(super) fn selected(
    document: &DocumentBinding,
    state: &mut DocumentState,
    request: &GitHubAuthRequest,
) -> Result<Option<accounts_wire::Witness>, BridgeError> {
    let Some(id) = &request.accounts_observation_id else {
        return Ok(None);
    };
    let Some(Entry::AccountsFinished(f)) = &state.gh_auth else {
        return Err(changed());
    };
    if !f.current(document, state)
        || f.status.project_id != request.project_id
        || f.status.repository != request.repository
        || f.status
            .accounts
            .as_ref()
            .is_none_or(|a| &a.observation_id != id || !a.logins.contains(&request.selected_login))
    {
        return Err(changed());
    }
    let (generation, root, witness) = (
        f.generation,
        f.root.clone(),
        f.witness.clone().ok_or_else(changed)?,
    );
    let observed = document
        .registry_result(
            state,
            document.inner.bridge.native_project(&request.project_id),
            None,
        )
        .map_err(|e| source_error(e.reason))?;
    if observed.0 != generation || observed.1 != root {
        return Err(changed());
    }
    Ok(Some(witness))
}

/// Like the existing Connect observer: bounded result DATA and Weak Document,
/// never a Registration/source/runtime backreference retained by the renderer.
pub(crate) struct Observer {
    document: Weak<Inner>,
    result: Arc<Mutex<Option<accounts_wire::Status>>>,
}
impl Observer {
    pub(crate) async fn returned(self) -> Result<accounts_wire::Status, BridgeError> {
        loop {
            if let Some(status) = self
                .result
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?
                .take()
            {
                return Ok(status);
            }
            let Some(inner) = self.document.upgrade() else {
                return Err(BridgeError::cleanup_unknown());
            };
            DocumentBinding { inner }.github_auth_public_status();
            if let Some(status) = self
                .result
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?
                .take()
            {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
impl DocumentBinding {
    pub(crate) fn github_auth_public_status(&self) -> accounts_wire::PublicStatus {
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        status(self, &state).map_or_else(
            || accounts_wire::PublicStatus::Connect(super::status(self, &state)),
            accounts_wire::PublicStatus::Accounts,
        )
    }
    pub(crate) fn github_auth_public_cancel(
        &self,
        id: &str,
    ) -> Result<accounts_wire::PublicStatus, BridgeError> {
        {
            let mut state = self.lock();
            if let Some(result) = cancel(self, &mut state, id) {
                return result.map(accounts_wire::PublicStatus::Accounts);
            }
        }
        self.github_auth_cancel(id)
            .map(accounts_wire::PublicStatus::Connect)
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn github_auth_accounts(
        &self,
        request: accounts_wire::Request,
    ) -> Result<Observer, BridgeError> {
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            feature = "custom-protocol",
            not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher")
        )))]
        {
            let _ = request;
            Err(github_session::refused(GitHubReason::RuntimeUnavailable))
        }
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            feature = "custom-protocol",
            not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher")
        ))]
        {
            if !request.bounded() {
                return Err(BridgeError::invalid());
            }
            if !entry_available(self) {
                return Err(github_session::refused(GitHubReason::RuntimeUnavailable));
            }
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            let gate = self.github_gate(&state);
            if gate != GitHubReason::None {
                return Err(github_session::refused(gate));
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
                || super::pending(&state)
            {
                return Err(github_session::refused(GitHubReason::Busy));
            }
            let idle_epoch = state
                .github
                .gh_auth_idle_epoch()
                .ok_or_else(|| github_session::refused(GitHubReason::Busy))?;
            let (generation, root) = self
                .registry_result(
                    &mut state,
                    self.inner.bridge.native_project(&request.project_id),
                    None,
                )
                .map_err(|e| source_error(e.reason))?;
            let future = asset_source::GhAuthSources::working_bytes()
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<OriginalWork>()
                            + std::mem::size_of::<Read>()
                            + entry_wire::ENTRY_BACKING,
                    )
                })
                .ok_or_else(BridgeError::invalid)?;
            lookup_memory::github_auth_admission_bytes(&self.inner, &state, future)
                .map_err(|_| github_session::refused(GitHubReason::Busy))?;
            let document_revision =
                status_successor(state.revision).ok_or_else(BridgeError::invalid)?;
            let id = self
                .next_operation(&mut state)
                .map_err(|e| source_error(e.reason))?;
            let end = Instant::now()
                .checked_add(WHOLE)
                .ok_or_else(BridgeError::invalid)?;
            let original = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
            original.set_endpoint(Some(end));
            let result = Arc::new(Mutex::new(None));
            let read = Arc::new(Read {
                original: original.clone(),
                document: Arc::downgrade(&self.inner),
                session_identity: self.inner.session_identity.clone(),
                native_context: state.context.clone(),
                native_session: state.session,
                idle_epoch,
                document_revision,
                generation,
                root,
                request,
                end,
                result: result.clone(),
                sources: Mutex::new(asset_source::GhAuthSources::new()),
                facts: Mutex::new(Facts {
                    entered: false,
                    closed: false,
                    body_returned: false,
                    final_join: None,
                    failure: None,
                    cleanup_end: None,
                    unknown: false,
                    witness: None,
                }),
            });
            let mut coordinator = original
                .coordinator
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            coordinator.receipt = JoinReceipt::Pending;
            state.gh_auth = Some(Entry::Accounts(read.clone()));
            let (start, enter) = oneshot::channel();
            let document = self.clone();
            let guard = Guard {
                read: read.clone(),
                _end: CoordinatorEnd(original.clone()),
                normal: false,
            };
            coordinator.handle = Some(tauri::async_runtime::spawn(async move {
                let mut guard = guard;
                if enter.await.is_err() {
                    read.fail(BridgeError::cleanup_unknown(), Instant::now());
                } else {
                    coordinate(&document, &read).await;
                }
                if let Ok(mut f) = read.facts.lock() {
                    f.body_returned = true;
                }
                guard.normal = true;
            }));
            drop(coordinator);
            if start.send(()).is_err() {
                original.stop();
            }
            self.bump(&mut state);
            Ok(Observer {
                document: Arc::downgrade(&self.inner),
                result,
            })
        }
    }
}
struct Guard {
    read: Arc<Read>,
    _end: CoordinatorEnd,
    normal: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.normal {
            self.read
                .fail(BridgeError::cleanup_unknown(), Instant::now());
        }
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn native_failure(
    read: &Read,
    first: Option<(
        mrk_macos_installed_native::vault_filesystem::Failure,
        Instant,
    )>,
) {
    use mrk_macos_installed_native::vault_filesystem::Failure;
    if let Some((cause, at)) = first {
        read.fail(
            match cause {
                Failure::Unknown => BridgeError::cleanup_unknown(),
                Failure::Stopped => cancelled(),
                _ => github_session::refused(GitHubReason::RuntimeUnavailable),
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
pub(super) struct ChildCall {
    pub(super) read: Arc<Read>,
    pub(super) close: bool,
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn execute_child(owner: &Arc<OriginalWork>, call: ChildCall) -> Result<(), Reason> {
    let r = call.read;
    if !Arc::ptr_eq(owner, &r.original) {
        return Err(Reason::CleanupUnknown);
    }
    let result = (|| {
        {
            let mut f = r.facts.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            let entered = if call.close {
                &mut f.closed
            } else {
                &mut f.entered
            };
            if *entered {
                return Err(BridgeError::cleanup_unknown());
            }
            *entered = true;
        }
        if call.close {
            if r.cleanup_expired() {
                return Err(BridgeError::cleanup_unknown());
            }
        } else {
            let document = DocumentBinding {
                inner: r
                    .document
                    .upgrade()
                    .ok_or_else(BridgeError::cleanup_unknown)?,
            };
            let mut state = document.lock();
            current(&document, &mut state, &r)?;
        }
        let mut sources = r
            .sources
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let result = if call.close {
            sources.close(&mut |first| {
                native_failure(&r, first);
                r.cleanup_expired()
            })
        } else {
            sources.inspect_accounts(&mut || owner.interrupted())
        };
        native_failure(&r, sources.first_failure());
        result.map_err(source_error)?;
        if call.close {
            if !sources.settled() {
                return Err(BridgeError::cleanup_unknown());
            }
        } else {
            let witness = sources.accounts_witness().map_err(source_error)?.clone();
            r.facts
                .lock()
                .map_err(|_| BridgeError::cleanup_unknown())?
                .witness = Some(witness);
        }
        Ok(())
    })();
    if let Err(error) = &result {
        r.fail(error.clone(), Instant::now());
    }
    result.map_err(|e| {
        if is_unknown(&e) {
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
async fn call(read: &Arc<Read>, close: bool) -> Result<(), BridgeError> {
    match child(
        &read.original,
        ChildJob::GitHubAuth(super::ChildCall::Accounts(ChildCall {
            read: read.clone(),
            close,
        })),
    )
    .await
    {
        Ok(ChildEnd::GitHubAuth(Ok(()))) => Ok(()),
        _ => Err(read.failure().unwrap_or_else(BridgeError::cleanup_unknown)),
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
async fn coordinate(document: &DocumentBinding, read: &Arc<Read>) {
    if let Err(error) = call(read, false).await {
        read.fail(error, Instant::now());
    }
    if read.failure().as_ref().is_some_and(is_unknown) {
        return;
    }
    if read.failure().is_none() {
        let mut state = document.lock();
        if let Err(error) = current(document, &mut state, read) {
            read.fail(error, Instant::now());
        }
    }
    if let Err(error) = call(read, true).await {
        read.fail(error, Instant::now());
    }
}
