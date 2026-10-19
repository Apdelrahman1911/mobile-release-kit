//! Fixed request-to-original-session handoff INSIDE EditOwner. The CLI cannot
//! construct this link, a window, a root lease, a Session or a native receipt.
//! Every hook below is bounded memory only: no Host/Service lock or IO.
use super::*;
use crate::{agent_identity_requests as requests, service_protocol::Id};
use std::sync::{OnceLock, Weak};

pub(super) struct Link {
    entry: Arc<requests::Entry>,
    owner: Weak<Inner>,
    registered: RegisteredEditRoot,
    operation: Id,
    generation: Id,
    marker: Arc<()>,
    session: OnceLock<Weak<Session>>,
}

fn platform(value: requests::Platform) -> identity_wire::Platform {
    match value {
        requests::Platform::Android => identity_wire::Platform::Android,
        requests::Platform::Ios => identity_wire::Platform::Ios,
    }
}
fn intent(value: requests::IdentityIntent) -> identity_wire::IdentityIntent {
    match value {
        requests::IdentityIntent::Preserve => identity_wire::IdentityIntent::Preserve,
        requests::IdentityIntent::NewApplication => identity_wire::IdentityIntent::NewApplication,
    }
}
fn matching_open(entry: &requests::Entry, args: &identity_wire::Open) -> bool {
    match args {
        identity_wire::Open::Edit {
            project_id,
            selection,
        } => {
            project_id == &entry.scope().runtime_id
                && selection.platform == platform(entry.input().change.selection.platform)
                && selection.target == entry.input().change.selection.target
                && selection.project == entry.input().change.selection.project
        }
        identity_wire::Open::Recover { .. } => false,
    }
}
fn matching_submission(change: &requests::Change, submission: &identity_wire::Submission) -> bool {
    match submission {
        identity_wire::Submission::Edit {
            desired_identity,
            identity_intent,
        } => {
            desired_identity == &change.desired_identity
                && *identity_intent == intent(change.identity_intent)
        }
        identity_wire::Submission::Recover => false,
    }
}
impl Link {
    pub(super) fn matches_open(&self, args: &identity_wire::Open) -> bool {
        matching_open(&self.entry, args)
    }
    fn active(&self, active: &ActiveOwner) -> bool {
        active.session.domain == EditDomain::ProjectIdentity
            && active.session.id == self.operation.as_str()
            && active.projection.session_id == self.operation.as_str()
            && active.projection.owner_generation == self.generation.as_str()
            && active.projection.project_id == self.entry.scope().runtime_id
            && active.session.registration.as_ref() == Some(&self.registered)
            && self
                .session
                .get()
                .is_some_and(|original| original.as_ptr() == Arc::as_ptr(&active.session))
            && self
                .entry
                .bound_to(self.operation.as_str(), self.generation.as_str())
    }
}

impl EditOwner {
    /// Called only by the genuine Document's fixed Review admission under its
    /// original lock, after native root/stamp checks. This attaches no observer
    /// to an old/replaced projection and grants nothing to a second Session.
    pub(crate) fn attach_agent_identity(
        &self,
        window: &str,
        ticket: &mut RegisteredOpenTicket,
        entry: Arc<requests::Entry>,
        registered: &RegisteredEditRoot,
    ) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ProjectIdentity)?;
        let document = self
            .inner
            .android_registration
            .get()
            .ok_or_else(invalid_owner)?;
        let scope = entry.scope();
        let (device, inode) = registered
            .root
            .identity
            .posix()
            .map_err(|_| invalid_owner())?
            .service_identity();
        if !Arc::ptr_eq(&ticket.owner, &self.inner)
            || ticket.domain != EditDomain::ProjectIdentity
            || ticket.identity.is_some()
            || ticket.agent_identity.is_some()
            || r.active.is_some()
            || !entry.admission_live(Instant::now())
            || scope.document.strong_count() == 0
            || !Weak::ptr_eq(&scope.document, &document.document)
            || registered.generation != scope.registration
            || registered.root.path != scope.root
            || device != scope.device
            || inode != scope.inode
        {
            return Err(invalid_owner());
        }
        let operation = Id::parse(&ticket.id).map_err(|_| invalid_owner())?;
        let generation = Id::parse(&r.generation).map_err(|_| invalid_owner())?;
        ticket.agent_identity = Some(Arc::new(Link {
            entry,
            owner: Arc::downgrade(&self.inner),
            registered: registered.clone(),
            operation,
            generation,
            marker: Arc::new(()),
            session: OnceLock::new(),
        }));
        Ok(())
    }

    /// A retained link, not caller SID/status, selects the active original for
    /// new Prepare/Apply. The ordinary endpoints ALSO check it in their shared
    /// common claims, so they cannot replace this proposal's desired identity.
    pub(crate) fn agent_identity_session(
        &self,
        window: &str,
        entry: &Arc<requests::Entry>,
    ) -> Result<String, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ProjectIdentity)?;
        let active = r.active.as_ref().ok_or_else(invalid_owner)?;
        let link = active
            .session
            .agent_identity
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if !Arc::ptr_eq(&link.entry, entry)
            || !link.active(active)
            || !entry.review_live(Instant::now())
        {
            return Err(invalid_owner());
        }
        Ok(active.session.id.clone())
    }

    /// Consent revocation is independent of service/IPC health. Request STOP
    /// through the same original owner and keep its joins/finality unchanged.
    pub(crate) fn revoke_agent_identity(&self) {
        let mut publication = self.inner.mandatory_publication();
        {
            let mut r = self.inner.lock();
            if let Some(active) = r
                .active
                .as_ref()
                .filter(|a| a.session.agent_identity.is_some())
            {
                let link = active
                    .session
                    .agent_identity
                    .as_ref()
                    .expect("filtered original link");
                link.entry.revoke();
                let id = active.session.id.clone();
                self.inner.trigger_locked(
                    &mut publication,
                    &mut r,
                    &id,
                    Reason::Cancelled,
                    Instant::now(),
                );
            }
        }
        publication.finish();
    }
}

/// Last preclaim check, under the same registry guard. A normal GUI ticket has
/// no link and retains its old behavior. There is no qualified-native bypass.
pub(super) fn before_claim(
    owner: &Arc<Inner>,
    r: &Registry,
    session: &Arc<Session>,
    project: &str,
) -> Result<(), BridgeError> {
    let Some(link) = &session.agent_identity else {
        return Ok(());
    };
    let document = owner.android_registration.get().ok_or_else(invalid_owner)?;
    if session.domain != EditDomain::ProjectIdentity
        || link.owner.as_ptr() != Arc::as_ptr(owner)
        || session.id != link.operation.as_str()
        || r.generation != link.generation.as_str()
        || project != link.entry.scope().runtime_id
        || session.registration.as_ref() != Some(&link.registered)
        || !Weak::ptr_eq(&link.entry.scope().document, &document.document)
        || link.session.get().is_some()
        || !link.entry.admission_live(Instant::now())
    {
        return Err(invalid_owner());
    }
    Ok(())
}
/// Immediately AFTER the original `*claimed = true`, before even constructing
/// the projection. No later returned failure may become "not started".
pub(super) fn claim_entered(session: &Session) {
    if let Some(link) = &session.agent_identity {
        link.entry.original_claim_entered();
    }
}
/// AFTER installing that very ActiveOwner, BEFORE history/bump/queue/GO. The
/// once-only SID is real even if later original task registration fails. Link
/// failure fences this request; it does not rewrite the independent core.
pub(super) fn linked(r: &Registry) {
    let Some(active) = &r.active else {
        return;
    };
    let Some(link) = &active.session.agent_identity else {
        return;
    };
    if active.session.id != link.operation.as_str()
        || active.projection.owner_generation != link.generation.as_str()
        || link.session.set(Arc::downgrade(&active.session)).is_err()
    {
        link.entry.unconfirmed();
        return;
    }
    let _ = link.entry.bind_original(
        link.operation.clone(),
        link.generation.clone(),
        Arc::downgrade(&link.marker),
    );
}
pub(super) fn prepare_allowed(
    active: &ActiveOwner,
    submission: &identity_wire::Submission,
    now: Instant,
) -> bool {
    active.session.agent_identity.as_ref().is_none_or(|link| {
        link.active(active)
            && link.entry.review_live(now)
            && matching_submission(&link.entry.input().change, submission)
    })
}
pub(super) fn apply_allowed(active: &ActiveOwner, now: Instant) -> bool {
    active
        .session
        .agent_identity
        .as_ref()
        .is_none_or(|link| link.active(active) && link.entry.review_live(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn change() -> requests::Change {
        requests::Change {
            selection: requests::Selection {
                platform: requests::Platform::Android,
                target: ":app".into(),
                project: None,
            },
            desired_identity: "com.example.fixture".into(),
            identity_intent: requests::IdentityIntent::NewApplication,
        }
    }
    #[test]
    fn bound_identity_submission_is_exact_including_new_application_intent() {
        let change = change();
        let exact = identity_wire::Submission::Edit {
            desired_identity: change.desired_identity.clone(),
            identity_intent: identity_wire::IdentityIntent::NewApplication,
        };
        assert!(matching_submission(&change, &exact));
        assert!(!matching_submission(
            &change,
            &identity_wire::Submission::Edit {
                desired_identity: "com.example.changed".into(),
                identity_intent: identity_wire::IdentityIntent::NewApplication
            }
        ));
        assert!(!matching_submission(
            &change,
            &identity_wire::Submission::Edit {
                desired_identity: change.desired_identity.clone(),
                identity_intent: identity_wire::IdentityIntent::Preserve
            }
        ));
        assert!(!matching_submission(
            &change,
            &identity_wire::Submission::Recover
        ));
    }
    #[test]
    fn proposal_grammar_is_data_not_an_owner_or_qualified_route() {
        let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/inert-agent-request-fixture",
        )));
        // A valid proposal supplies neither the original main window nor the
        // genuine Document/native profile. No Session/native work is created.
        assert!(change().validate().is_ok());
        assert!(owner.identity_open_ticket("main").is_err());
        assert!(owner.inner.lock().active.is_none());
    }
}
