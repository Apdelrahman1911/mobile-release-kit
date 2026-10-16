//! Original document/registry/edit custody for five-file setup publication.
use super::*;
use crate::{github_connection_session::publication as s, github_publication_protocol as p};

pub(crate) struct GitHubPublicationGoGate {
    inner: Weak<Inner>,
}
impl GitHubPublicationGoGate {
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
        // No lock gap before one-use original GO. The caller supplies no token,
        // source path/identity, raw config, JSON body or alternate edit witness.
        state.github.publication_go(
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
        let command =
            p::decode_command(name, value).map_err(|_| s::refused(p::Reason::InvalidInput))?;
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
        let gate = GitHubPublicationGoGate {
            inner: Arc::downgrade(&self.inner),
        };
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        match command {
            p::Command::Prepare(args) => {
                let source = source(&root)?;
                let stamp = edit.stamp()?;
                state.github.publication_prepare(
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
