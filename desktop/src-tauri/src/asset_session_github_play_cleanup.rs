//! Hosted Play cleanup uses the original document/registry/edit and Setup custodian.
use super::*;
use crate::{github_connection_session::play_cleanup as s, github_play_cleanup_protocol as p};

pub(crate) struct GitHubPlayCleanupGoGate {
    inner: Weak<Inner>,
    agent: Option<Arc<crate::service_play_cleanup_requests::NativeLink>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    service: Option<Weak<crate::application_service::ApplicationService>>,
}

impl GitHubPlayCleanupGoGate {
    pub(crate) fn agent(&self) -> Option<&Arc<crate::service_play_cleanup_requests::NativeLink>> {
        self.agent.as_ref()
    }
    // Original owners-lock boundary. No Doc/Host/Service mutex or IO here.
    pub(crate) fn agent_arm(&self, id: &str) -> Result<(), BridgeError> {
        if let Some(link) = &self.agent {
            self.agent_service_current()?;
            link.arm(id)
                .map_err(|_| s::refused(p::Reason::ConsentExpired))?;
        }
        Ok(())
    }
    fn agent_service_current(&self) -> Result<(), BridgeError> {
        if self.agent.is_none() {
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let original = self
                .service
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or_else(|| s::refused(p::Reason::ConsentExpired))?;
            original
                .native_history_current()
                .map_err(|_| s::refused(p::Reason::CleanupUnknown))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(s::refused(p::Reason::Unqualified))
        }
    }
    /// Sampled by the SAME native watchdog, never an alternate timer/owner.
    /// Only original facet/inbox/service poison atomics and short memory locks.
    pub(crate) fn agent_first_stop(&self) -> Option<(bool, Instant)> {
        let link = self.agent.as_ref()?;
        if self.agent_service_current().is_err() {
            link.entry().unknown();
        }
        match link.entry().watchdog_stop() {
            Ok(Some(cut)) => Some(cut),
            Ok(None) => None,
            Err(_) => {
                link.entry().unknown();
                Some((true, Instant::now()))
            }
        }
    }

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
        self.agent_service_current()?;
        if let Some(link) = &self.agent {
            link.current(true)
                .map_err(|_| s::refused(p::Reason::ConsentExpired))?;
        }
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
            .play_cleanup_profile_available()
        {
            return Err(s::refused(p::Reason::Unqualified));
        }
        let project = state
            .github
            .play_cleanup_registered_project()
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
        if let Some(link) = &self.agent {
            if !document
                .inner
                .android_registration_control
                .matches_epoch(link.scope().input_revision)
            {
                return Err(s::refused(p::Reason::TargetChanged));
            }
        }
        // No lock gap before one-use original GO. The caller supplies no token,
        // source path/identity, raw config, JSON body or alternate edit witness.
        state.github.play_cleanup_go(
            id,
            digest,
            request,
            generation,
            &root,
            &edit,
            Instant::now(),
            claim,
        )
    }
}
fn source(root: &asset_source::RegisteredRoot) -> Result<p::Source, BridgeError> {
    let path = root
        .path
        .to_str()
        .filter(|v| v.starts_with('/') && v.len() <= 4096 && !v.chars().any(char::is_control))
        .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
    let identity = root
        .identity
        .posix()
        .map_err(|_| s::refused(p::Reason::TargetChanged))?
        .preflight_identity();
    let value = p::Source {
        root: path.to_owned(),
        root_identity: crate::github_setup_protocol::SecretRootIdentity {
            device: identity.device,
            inode: identity.inode,
            mode: identity.mode,
            uid: identity.uid,
            gid: identity.gid,
        },
    };
    if !value.valid() {
        return Err(s::refused(p::Reason::TargetChanged));
    }
    Ok(value)
}
impl DocumentBinding {
    pub(super) fn play_cleanup_observe_locked(
        &self,
        state: &mut DocumentState,
        now: Instant,
        external: GitHubReason,
    ) {
        let project = state
            .github
            .play_cleanup_registered_project()
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
                Ok(edit) => state.github.reconcile_play_cleanup(
                    now,
                    external,
                    Some((generation, &root, &edit)),
                ),
                Err(error) => {
                    if error.code == "cleanup_unknown" {
                        state.github.unknown();
                    }
                    state.github.reconcile_play_cleanup(now, external, None);
                }
            }
        } else {
            state.github.reconcile_play_cleanup(now, external, None);
        }
    }
    pub(crate) fn play_cleanup_status(&self) -> p::Status {
        let mut state = self.lock();
        let now = Instant::now();
        self.expire(&mut state, now);
        let external = self.github_gate(&state);
        state.github.play_cleanup_status(
            self.inner
                .bridge
                .supervisor
                .play_cleanup_profile_available(),
            now,
            external,
        )
    }
    pub(crate) fn play_cleanup_command(
        &self,
        name: &str,
        value: &Value,
    ) -> Result<p::Status, BridgeError> {
        let command =
            p::decode_command(name, value).map_err(|_| s::refused(p::Reason::InvalidInput))?;
        if matches!(command, p::Command::Status) {
            return Ok(self.play_cleanup_status());
        }
        if let p::Command::AllowAgent(args) = command {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                return self.play_cleanup_allow_agent(args);
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                return Err(s::refused(p::Reason::Unqualified));
            }
        }
        self.play_cleanup_execute(
            command,
            None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
        )
    }
    pub(super) fn play_cleanup_execute(
        &self,
        command: p::Command,
        agent: Option<Arc<crate::service_play_cleanup_requests::NativeLink>>,
        #[cfg(any(target_os = "linux", target_os = "macos"))] service: Option<
            Weak<crate::application_service::ApplicationService>,
        >,
    ) -> Result<p::Status, BridgeError> {
        let nonce = if matches!(command, p::Command::Prepare(_) | p::Command::Pending(_)) {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| s::refused(p::Reason::RuntimeUnavailable))?;
            Some(bytes.iter().map(|v| format!("{v:02x}")).collect::<String>())
        } else {
            None
        };
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        match &command {
            p::Command::Cancel(args) => {
                return state.github.play_cleanup_cancel(&args.operation_id)
            }
            p::Command::Discard(args) => return state.github.play_cleanup_discard(args),
            _ => {}
        }
        let external = self.github_gate(&state);
        let available = state.github.play_cleanup_status(
            self.inner
                .bridge
                .supervisor
                .play_cleanup_profile_available(),
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
        if let Some(link) = &agent {
            if !Arc::ptr_eq(
                &link
                    .scope()
                    .document
                    .upgrade()
                    .ok_or_else(|| s::refused(p::Reason::ConsentExpired))?,
                &self.inner.session_identity,
            ) || link.scope().runtime_id != project
                || !self
                    .inner
                    .android_registration_control
                    .matches_epoch(link.scope().input_revision)
            {
                return Err(s::refused(p::Reason::TargetChanged));
            }
        }
        // Same whole-Document census including all old owner/history/IPC buffers.
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        let retained = lookup_memory::retained_document_bytes(&self.inner, &state)
            .map_err(|_| s::refused(p::Reason::ResourcesUnavailable))?;
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        let retained = usize::MAX; // Closed unsupported path; no quota/currentness fallback.
        p::admission_bytes(retained).ok_or_else(|| s::refused(p::Reason::ResourcesUnavailable))?;
        let gate = GitHubPlayCleanupGoGate {
            inner: Arc::downgrade(&self.inner),
            agent,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            service,
        };
        gate.agent_service_current()?;
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        match command {
            p::Command::Prepare(args) => {
                let source = source(&root)?;
                let stamp = edit.stamp()?;
                state.github.play_cleanup_prepare(
                    args,
                    generation,
                    root,
                    &binding,
                    stamp,
                    nonce.ok_or_else(BridgeError::invalid)?,
                    source,
                    gate,
                    supervisor,
                    now,
                )
            }
            p::Command::Start(args) => {
                let source = source(&root)?;
                let home = github_preflight_home()?;
                state.github.play_cleanup_start(
                    args, generation, root, &binding, &edit, source, home, gate, supervisor, now,
                )
            }
            p::Command::Pending(args) => {
                let stamp = edit.stamp()?;
                let home = github_preflight_home()?;
                state.github.play_cleanup_pending(
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
            p::Command::Observe(args) => {
                let stamp = edit.stamp()?;
                let home = github_preflight_home()?;
                state.github.play_cleanup_observe(
                    args, generation, root, &binding, stamp, home, gate, supervisor, now,
                )
            }
            _ => Err(s::refused(p::Reason::InvalidInput)),
        }
    }
}

#[cfg(all(
    test,
    any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )
))]
#[path = "asset_session_github_play_cleanup_tests.rs"]
mod tests;
