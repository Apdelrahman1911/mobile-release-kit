//! Original document/registry/edit custody for five-file setup publication.
use super::*;
use crate::{github_connection_session::publication as s, github_publication_protocol as p};

pub(crate) struct GitHubPublicationGoGate {
    agent: Option<Arc<crate::service_github_action_requests::Entry>>,
    inner: Weak<Inner>,
    counter: Option<Arc<version_counter_setup::Facet>>,
}
impl GitHubPublicationGoGate {
    pub(crate) fn agent(&self) -> Option<&Arc<crate::service_github_action_requests::Entry>> { self.agent.as_ref() }
    pub(crate) fn agent_entering(&self) -> Result<(), BridgeError> {
        if let Some(e) = &self.agent { e.entering().map_err(application_service::public_error)?; }
        Ok(())
    }
    pub(crate) fn select_target(&mut self, target: p::Target) -> Result<p::Selection, BridgeError> {
        match self.counter.as_mut() {
            Some(facet) => Arc::get_mut(facet)
                .ok_or_else(BridgeError::cleanup_unknown)?
                .bind(target),
            None => Ok(target.into()),
        }
    }
    pub(crate) fn counter_quote(&self) -> Option<usize> {
        self.counter.as_ref().map_or(Some(0), |v| v.quote())
    }
    pub(crate) async fn prepare_counter(
        &self,
        control: crate::supervisor::PublicationControl,
    ) -> Result<(), BridgeError> {
        match &self.counter {
            Some(facet) => facet.prepare(control).await,
            None => Ok(()),
        }
    }
    pub(crate) async fn finalize_counter(
        &self,
        control: crate::supervisor::PublicationControl,
    ) -> bool {
        match &self.counter {
            Some(facet) => facet.finalize(control).await,
            None => true,
        }
    }
    pub(crate) fn counter_settled(&self) -> bool {
        self.counter.as_ref().is_none_or(|v| v.settled())
    }
    pub(crate) fn counter_proof(&self) -> Option<Arc<CounterStateProof>> {
        self.counter.as_ref()?.retired_proof()
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
            .github_publication_profile_available()
        {
            return Err(s::refused(p::Reason::Unqualified));
        }
        let project = state
            .github
            .publication_registered_project()
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
        let counter_project = match (request.target.counter(), &self.counter) {
            (Some(target), Some(facet))
                if matches!(request.kind, p::Kind::Prepare | p::Kind::Publish) =>
            {
                if !facet.current_locked(&document, &state, &edit) {
                    return Err(s::refused(p::Reason::CounterStateChanged));
                }
                let project = facet
                    .project_before_go()
                    .ok_or_else(BridgeError::cleanup_unknown)?;
                if target.project_id.as_deref().is_some_and(|id| id != project) {
                    return Err(s::refused(p::Reason::CounterStateChanged));
                }
                Some(project)
            }
            (Some(target), None) if request.kind == p::Kind::Reconcile => target.project_id.clone(),
            (None, None) => None,
            _ => return Err(BridgeError::cleanup_unknown()),
        };
        // No lock gap before one-use original GO. The caller supplies no token,
        // source path/identity, raw config, JSON body or alternate edit witness.
        if let Some(e) = &self.agent { e.current(true).map_err(application_service::public_error)?; }
        state.github.publication_go(
            id,
            digest,
            request,
            generation,
            &root,
            &edit,
            Instant::now(),
            counter_project.as_deref(),
            || {
                let granted = claim();
                if granted { if let Some(e) = &self.agent {
                    if e.go(id).is_err() { e.unknown(crate::service_github_action_protocol::Reason::CleanupUnknown); return false; }
                } }
                granted
            },
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
    pub(super) fn github_publication_observe_locked(
        &self,
        state: &mut DocumentState,
        now: Instant,
        external: GitHubReason,
    ) {
        let project = state
            .github
            .publication_registered_project()
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
                Ok(edit) => state.github.reconcile_publication(
                    now,
                    external,
                    Some((generation, &root, &edit)),
                ),
                Err(error) => {
                    if error.code == "cleanup_unknown" {
                        state.github.unknown();
                    }
                    state.github.reconcile_publication(now, external, None);
                }
            }
        } else {
            state.github.reconcile_publication(now, external, None);
        }
    }
    pub(crate) fn github_publication_status(&self) -> p::Status {
        let mut state = self.lock();
        let now = Instant::now();
        self.expire(&mut state, now);
        let external = self.github_gate(&state);
        state.github.publication_status(
            self.inner
                .bridge
                .supervisor
                .github_publication_profile_available(),
            now,
            external,
        )
    }
    pub(crate) fn github_publication_command(
        &self,
        name: &str,
        value: &Value,
    ) -> Result<p::Status, BridgeError> {
        self.github_publication_command_at(name, value, None)
    }
    /// Native app-local-data resolution only; no renderer/env path is accepted.
    pub(crate) fn github_publication_command_at(
        &self,
        name: &str,
        value: &Value,
        app_data: Option<std::path::PathBuf>,
    ) -> Result<p::Status, BridgeError> {
        let command =
            p::decode_command(name, value).map_err(|_| s::refused(p::Reason::InvalidInput))?;
        self.github_publication_execute(command, app_data, None)
    }
    pub(super) fn github_publication_execute(
        &self, command: p::Command, app_data: Option<std::path::PathBuf>,
        agent: Option<Arc<crate::service_github_action_requests::Entry>>,
    ) -> Result<p::Status, BridgeError> {
        if agent.as_ref().is_some_and(|e|!e.scope().review.kind().dispatch_family()) && !matches!(command, p::Command::Publish(_) | p::Command::Reconcile(_)) {
            return Err(s::refused(p::Reason::InvalidInput));
        }
        if matches!(command, p::Command::Status) {
            return Ok(self.github_publication_status());
        }
        let nonce = if matches!(command, p::Command::Prepare(_) | p::Command::Pending(_)) {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| s::refused(p::Reason::RuntimeUnavailable))?;
            Some(bytes.iter().map(|v| format!("{v:02x}")).collect::<String>())
        } else {
            None
        };
        let ledger_id = if matches!(&command,p::Command::Prepare(v) if v.purpose==Some(p::counter::Purpose::Counter))
        {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| s::refused(p::Reason::RuntimeUnavailable))?;
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            let text = bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
            Some(format!(
                "{}-{}-{}-{}-{}",
                &text[..8],
                &text[8..12],
                &text[12..16],
                &text[16..20],
                &text[20..]
            ))
        } else {
            None
        };
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        match &command {
            p::Command::Cancel(args) => return state.github.publication_cancel(&args.operation_id),
            p::Command::Discard(args) => return state.github.publication_discard(args),
            _ => {}
        }
        let external = self.github_gate(&state);
        let available = state.github.publication_status(
            self.inner
                .bridge
                .supervisor
                .github_publication_profile_available(),
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
        // The explicit native identity check precedes counter state/native
        // app-data resolution and home/source acquisition. Counter keeps its SAME native Facet.
        if let Some(e)=agent.as_ref().filter(|e|!e.scope().review.kind().dispatch_family()){
            state.github.publication_agent_current(&command,e,generation,&root,&edit,Instant::now())?;
        } else {
            state.github.counter_agent_entry(&command,agent.as_ref(),generation,&root,&binding,&edit,Instant::now())?;
        }
        let counter = match &command {
            p::Command::Prepare(args) if args.purpose == Some(p::counter::Purpose::Counter) => {
                Some(version_counter_setup::Facet::new(
                    self,
                    &state,
                    &project,
                    generation,
                    &format!("refs/heads/{}", args.base),
                    &edit,
                    app_data,
                    ledger_id.ok_or_else(BridgeError::invalid)?,
                    None,
                )?)
            }
            p::Command::Publish(args) => {
                match state.github.publication_counter_inputs(&args.consent_id) {
                    Some((target, proof)) => Some(version_counter_setup::Facet::new(
                        self,
                        &state,
                        &project,
                        generation,
                        &format!("refs/heads/{}", target.base),
                        &edit,
                        app_data,
                        target.ledger_id,
                        Some(proof),
                    )?),
                    None => None,
                }
            }
            _ => None,
        };
        // Same complete Document/installation census; counter has no new pool.
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        if counter.is_some() || agent.is_some() {
            let bytes = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| s::refused(p::Reason::ResourcesUnavailable))?
                .checked_add(
                    installation_memory::additional_document_bytes(self, &state)
                        .map_err(|_| s::refused(p::Reason::ResourcesUnavailable))?,
                )
                .ok_or_else(|| s::refused(p::Reason::ResourcesUnavailable))?;
            let future = crate::macos_history_inventory::CODE_CONTROL_RESERVE
                .checked_add(p::RETAINED_LIMIT)
                .ok_or_else(|| s::refused(p::Reason::ResourcesUnavailable))?;
            crate::macos_history_inventory::admission_bytes(bytes, future)
                .ok_or_else(|| s::refused(p::Reason::ResourcesUnavailable))?;
        }
        let gate = GitHubPublicationGoGate {
            agent,
            inner: Arc::downgrade(&self.inner),
            counter,
        };
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        match command {
            p::Command::Prepare(args) => {
                let source = source(&root)?;
                let stamp = edit.stamp()?;
                let home = if args.purpose.is_some() {
                    Some(github_preflight_home()?)
                } else {
                    None
                };
                state.github.publication_prepare(
                    args,
                    generation,
                    root,
                    &binding,
                    stamp,
                    nonce.ok_or_else(BridgeError::invalid)?,
                    source,
                    home,
                    gate,
                    supervisor,
                    now,
                )
            }
            p::Command::Publish(args) => {
                let source = source(&root)?;
                let home = github_preflight_home()?;
                state.github.publication_publish(
                    args, generation, root, &binding, &edit, source, home, gate, supervisor, now,
                )
            }
            p::Command::Pending(args) => {
                let stamp = edit.stamp()?;
                let home = github_preflight_home()?;
                state.github.publication_pending(
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
                state.github.publication_reconcile(
                    args, generation, root, &binding, stamp, home, gate, supervisor, now,
                )
            }
            _ => Err(s::refused(p::Reason::InvalidInput)),
        }
    }
}
