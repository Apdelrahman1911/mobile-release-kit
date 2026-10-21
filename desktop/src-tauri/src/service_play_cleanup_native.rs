//! Fixed delegation of a genuine retained cleanup Consent, never a headless
//! review/provider runner. Service/Host IO occurs only outside Doc/Edit.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    github_connection_session::play_cleanup as session,
    github_play_cleanup_protocol as p, service_play_cleanup_protocol as wire,
    service_play_cleanup_requests as requests,
    service_protocol::{Error, Id},
};

fn public(error: Error) -> BridgeError {
    application_service::public_error(error)
}
fn same(a: &NativeProject, b: &NativeProject) -> bool {
    a.runtime_id == b.runtime_id
        && a.canonical_root == b.canonical_root
        && (a.device, a.inode) == (b.device, b.inode)
        && a.registration_generation == b.registration_generation
        && a.input_revision == b.input_revision
        && Arc::ptr_eq(&a.document_identity, &b.document_identity)
}
impl DocumentBinding {
    fn play_cleanup_review_native(
        &self,
        state: &mut DocumentState,
        args: &p::StartArgs,
    ) -> Result<(session::AgentReview, NativeProject), BridgeError> {
        self.expire(state, Instant::now());
        let external = self.github_gate(state);
        let status = state.github.play_cleanup_status(
            self.inner
                .bridge
                .supervisor
                .play_cleanup_profile_available(),
            Instant::now(),
            external,
        );
        if !status.available {
            return Err(session::refused(status.reason));
        }
        let (project, registered) = state
            .github
            .registration()
            .map(|(id, g)| (id.to_owned(), g))
            .ok_or_else(|| session::refused(p::Reason::NotConnected))?;
        let (generation, root) = self
            .registry_result(state, self.inner.bridge.native_project(&project), None)
            .map_err(|_| session::refused(p::Reason::TargetChanged))?;
        if generation != registered {
            return Err(session::refused(p::Reason::TargetChanged));
        }
        let binding = github_setup_project_binding(&root)
            .map_err(|_| session::refused(p::Reason::TargetChanged))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let review = state.github.play_cleanup_agent_review(
            args,
            generation,
            &root,
            &binding,
            &edit,
            Instant::now(),
        )?;
        let native = self.service_project_locked(state, &project)?;
        if native.canonical_root != root.path || native.registration_generation != generation {
            return Err(session::refused(p::Reason::TargetChanged));
        }
        Ok((review, native))
    }
    pub(super) fn play_cleanup_allow_agent(
        &self,
        args: p::StartArgs,
    ) -> Result<p::Status, BridgeError> {
        let (review, native) = {
            let mut state = self.lock();
            self.play_cleanup_review_native(&mut state, &args)?
        };
        // These are the genuine existing Host/Store methods; they do IO.
        // No lock from the first native capture survives this boundary.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service
            .play_cleanup_point(&native.runtime_id)
            .map_err(public)?;
        if point.saved.root != native.canonical_root
            || (point.saved.device, point.saved.inode) != (native.device, native.inode)
        {
            return Err(public(Error::Conflict));
        }
        let mut state = self.lock();
        let (current, current_native) = self.play_cleanup_review_native(&mut state, &args)?;
        if !Arc::ptr_eq(&review.identity, &current.identity)
            || !same(&native, &current_native)
            || !self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?
                .matches(&review.stamp)
            || state
                .github
                .play_cleanup_service()
                .is_some_and(|s| !Arc::ptr_eq(&s, &service))
        {
            return Err(public(Error::Conflict));
        }
        service.native_history_current().map_err(public)?; // Atomic only; never Service.lock.
        let scope = service.play_cleanup_requests().scope(
            point.saved.project_id,
            native.runtime_id,
            Id::parse(&review.id).map_err(public)?,
            review.end.min(point.read.end()),
            point.read,
            Arc::downgrade(&self.inner.session_identity),
            Arc::downgrade(&review.identity),
            self.inner.changes.clone(),
            native.input_revision,
        );
        let access = service
            .play_cleanup_requests()
            .allow(scope.clone())
            .map_err(public)?;
        // Return this exact installed snapshot while still holding SAME Doc.
        // A CLI consuming it after unlock cannot rewrite the Allow response.
        let result =
            state
                .github
                .play_cleanup_agent_allow(&review, scope.clone(), access, &service);
        if result.is_err() {
            scope.revoke(wire::Reason::ContextChanged, Instant::now());
        }
        result
    }
    /// Called by the existing retained shell relay. Supervisor owns actual
    /// asynchronous work; no unretained future or nested executor is created.
    pub(crate) fn play_cleanup_agent_tick(&self) {
        let service = {
            let state = self.lock();
            state.github.play_cleanup_service()
        };
        let Some(service) = service else { return };
        let claim = match service.play_cleanup_requests().claim() {
            Ok(Some(c)) => c,
            _ => return,
        };
        let link = claim.link().clone();
        let result = (|| {
            // Same current live READ/alias/Store proof, outside Doc.
            let point = service
                .play_cleanup_point(&link.scope().runtime_id)
                .map_err(public)?;
            if point.saved.project_id != link.scope().project_id
                || !Arc::ptr_eq(&point.read, &link.scope().read)
            {
                return Err(public(Error::Conflict));
            }
            let args = {
                let mut state = self.lock();
                self.expire(&mut state, Instant::now());
                service.native_history_current().map_err(public)?;
                let native = self.service_project_locked(&state, &link.scope().runtime_id)?;
                if native.canonical_root != point.saved.root
                    || (native.device, native.inode) != (point.saved.device, point.saved.inode)
                    || native.input_revision != link.scope().input_revision
                    || link
                        .scope()
                        .document
                        .upgrade()
                        .is_none_or(|d| !Arc::ptr_eq(&d, &native.document_identity))
                    || state
                        .github
                        .play_cleanup_service()
                        .is_none_or(|s| !Arc::ptr_eq(&s, &service))
                {
                    return Err(public(Error::Conflict));
                }
                state.github.play_cleanup_agent_start_args(&link)?
            };
            self.play_cleanup_execute(
                p::Command::Start(args),
                Some(link.clone()),
                Some(Arc::downgrade(&service)),
            )
        })();
        match result {
            Ok(status) => {
                let id = status
                    .operation
                    .as_ref()
                    .filter(|o| o.kind == p::Kind::Dispatch)
                    .map(|o| o.id.as_str());
                match id {
                    Some(id) => {
                        let _ = claim.handoff(id);
                    }
                    None => {
                        drop(claim);
                    }
                }
            }
            Err(error) => {
                let code = if error.code == "cleanup_unknown" || error.code == "cli_access_unknown"
                {
                    Error::StateUnknown
                } else if error.code.contains("busy") {
                    Error::Busy
                } else {
                    Error::Conflict
                };
                let _ = claim.not_admitted(code);
            }
        }
    }
    pub(crate) fn play_cleanup_agent_relay_closed(&self) {
        let mut state = self.lock();
        state.github.play_cleanup_agent_close(Instant::now());
    }
}
