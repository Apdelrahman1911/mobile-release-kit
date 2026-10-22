//! Draft pull request creation uses the original document/registry/edit and Setup custodian.
use super::*;
use crate::{github_connection_session::pull_request as s, github_pull_request_protocol as p};

pub(crate) struct GitHubPullRequestGoGate {
    agent: Option<Arc<crate::service_github_action_requests::Entry>>,
    inner: Weak<Inner>,
}
impl GitHubPullRequestGoGate {
    pub(crate) fn agent(&self)->Option<&Arc<crate::service_github_action_requests::Entry>>{self.agent.as_ref()}
    pub(crate) fn agent_entering(&self)->Result<(),BridgeError>{if let Some(e)=&self.agent{e.entering().map_err(application_service::public_error)?;}Ok(())}

    pub(crate) fn claim(
        &self,
        id: &str,
        digest: &str,
        request: &p::Request,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let document = DocumentBinding {
            inner: self
                .inner
                .upgrade()
                .ok_or_else(|| s::refused(p::Reason::Cancelled))?,
        };
        let mut state = document.lock();
        document.expire(&mut state, Instant::now());
        let external = document.github_gate(&state);
        if external != GitHubReason::None {
            return Err(s::refused(s::connection_reason(external)));
        }
        if !document
            .inner
            .bridge
            .supervisor
            .pull_request_profile_available()
        {
            return Err(s::refused(p::Reason::Unqualified));
        }
        let project = state
            .github
            .pull_request_registered_project()
            .map(str::to_owned)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        let (generation, root) = document
            .registry_result(
                &mut state,
                document.inner.bridge.native_project(&project),
                None,
            )
            .map_err(|v| {
                s::refused(if v.reason == Reason::CleanupUnknown {
                    p::Reason::CleanupUnknown
                } else {
                    p::Reason::TargetChanged
                })
            })?;
        let edit = document
            .inner
            .bridge
            .edits
            .saved_registration_guard(&document.inner.session_identity)
            .map_err(|v| {
                s::refused(if v.code == "cleanup_unknown" {
                    p::Reason::CleanupUnknown
                } else {
                    p::Reason::TargetChanged
                })
            })?;
        // No lock gap before one-use original GO. The caller supplies no token,
        // source path/identity, raw config, JSON body or alternate edit witness.
        if let Some(e)=&self.agent { e.current(true).map_err(application_service::public_error)?; }
        state.github.pull_request_go(
            id,
            digest,
            request,
            generation,
            &root,
            &edit,
            Instant::now(),
            || { let granted=claim(); if granted { if let Some(e)=&self.agent { if e.go(id).is_err() { e.unknown(crate::service_github_action_protocol::Reason::CleanupUnknown); return false; } } } granted },
        )
    }
}
impl DocumentBinding {
    pub(super) fn pull_request_observe_locked(
        &self,
        state: &mut DocumentState,
        now: Instant,
        external: GitHubReason,
    ) {
        let project = state
            .github
            .pull_request_registered_project()
            .map(str::to_owned);
        let original = project.as_deref().and_then(|id| {
            self.github_setup_registry_result(state, self.inner.bridge.native_project(id))
        });
        if let Some((generation, root)) = original {
            match self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)
            {
                Ok(edit) => state.github.reconcile_pull_request(
                    now,
                    external,
                    Some((generation, &root, &edit)),
                ),
                Err(error) => {
                    if error.code == "cleanup_unknown" {
                        state.github.unknown();
                    }
                    state.github.reconcile_pull_request(now, external, None);
                }
            }
        } else {
            state.github.reconcile_pull_request(now, external, None);
        }
    }
    pub(crate) fn pull_request_status(&self) -> p::Status {
        let mut state = self.lock();
        let now = Instant::now();
        self.expire(&mut state, now);
        let external = self.github_gate(&state);
        state.github.pull_request_status(
            self.inner
                .bridge
                .supervisor
                .pull_request_profile_available(),
            now,
            external,
        )
    }
    pub(crate) fn pull_request_command(
        &self,
        name: &str,
        value: &Value,
    ) -> Result<p::Status, BridgeError> {
        let command =
            p::decode_command(name, value).map_err(|_| s::refused(p::Reason::InvalidInput))?;
        self.pull_request_execute(command,None)
    }
    pub(super) fn pull_request_execute(&self, command:p::Command, agent:Option<Arc<crate::service_github_action_requests::Entry>>)->Result<p::Status,BridgeError>{
        if matches!(command, p::Command::Status) {
            return Ok(self.pull_request_status());
        }
        let nonce = if matches!(command, p::Command::Prepare(_) | p::Command::Pending(_)) {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| s::refused(p::Reason::RuntimeUnavailable))?;
            Some(bytes.iter().map(|v| format!("{v:02x}")).collect::<String>())
        } else {
            None
        };
        let mut state = self.lock();
        state.github.pull_request_operation_origin(&command, agent.as_ref())?;
        self.expire(&mut state, Instant::now());
        match &command {
            p::Command::Cancel(args) => {
                return state.github.pull_request_cancel(&args.operation_id)
            }
            p::Command::Discard(args) => return state.github.pull_request_discard(args),
            _ => {}
        }
        let external = self.github_gate(&state);
        let available = state.github.pull_request_status(
            self.inner
                .bridge
                .supervisor
                .pull_request_profile_available(),
            Instant::now(),
            external,
        );
        if !available.available {
            return Err(s::refused(available.reason));
        }
        let (project, original) = state
            .github
            .registration()
            .map(|(id, n)| (id.to_owned(), n))
            .ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let (generation, root) = self
            .registry_result(&mut state, self.inner.bridge.native_project(&project), None)
            .map_err(|v| {
                s::refused(if v.reason == Reason::CleanupUnknown {
                    p::Reason::CleanupUnknown
                } else {
                    p::Reason::TargetChanged
                })
            })?;
        if generation != original {
            return Err(s::refused(p::Reason::TargetChanged));
        }
        let binding = github_setup_project_binding(&root)
            .map_err(|_| s::refused(p::Reason::TargetChanged))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)
            .map_err(|v| {
                s::refused(if v.code == "cleanup_unknown" {
                    p::Reason::CleanupUnknown
                } else {
                    p::Reason::Busy
                })
            })?;
        state.github.pull_request_operation_entry(&command, agent.as_ref(), generation, &root, &binding, &edit, Instant::now())?;
        let gate = GitHubPullRequestGoGate {
            agent,
            inner: Arc::downgrade(&self.inner),
        };
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        match command {
            p::Command::Prepare(args) => {
                let stamp = edit.stamp()?;
                state.github.pull_request_prepare(
                    args,
                    generation,
                    root,
                    &binding,
                    stamp,
                    nonce.ok_or_else(BridgeError::invalid)?,
                    gate,
                    supervisor,
                    now,
                )
            }
            p::Command::Create(args) => {
                let home = github_preflight_home()?;
                state.github.pull_request_create(
                    args, generation, root, &binding, &edit, home, gate, supervisor, now,
                )
            }
            p::Command::Pending(args) => {
                let stamp = edit.stamp()?;
                let home = github_preflight_home()?;
                state.github.pull_request_pending(
                    args,
                    generation,
                    root,
                    &binding,
                    stamp,
                    nonce.ok_or_else(BridgeError::invalid)?,
                    home,
                    gate,
                    supervisor,
                    now,
                )
            }
            p::Command::Reconcile(args) => {
                let stamp = edit.stamp()?;
                let home = github_preflight_home()?;
                state.github.pull_request_reconcile(
                    args, generation, root, &binding, stamp, home, gate, supervisor, now,
                )
            }
            _ => Err(s::refused(p::Reason::InvalidInput)),
        }
    }
}
