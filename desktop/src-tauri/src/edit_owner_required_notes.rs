//! One fixed private-note adapter inside the ORIGINAL EditOwner. Awaiters only
//! observe its change notification; they own no executor, deadline or cleanup.
use super::*;
use crate::{asset_session::DocumentBinding, required_notes_commands as commands};

fn matches_request(projection: &EditProjection, generation: &str, request: u32, session: Option<&str>) -> bool {
    projection.domain == EditDomain::RequiredNotes && projection.owner_generation == generation
        && session.is_none_or(|id| projection.session_id == id)
        && projection.required_notes.as_ref().is_some_and(|detail|
            detail.binding.window_generation == generation && detail.binding.request_id == request)
}
fn matches_original(projection: &EditProjection, project: &str, binding: &notes_wire::Binding, session: &str) -> bool {
    matches_request(projection, &binding.window_generation, binding.request_id, Some(session))
        && projection.project_id == project && projection.required_notes.as_ref().is_some_and(|detail| detail.binding == *binding)
}

impl Inner {
    pub(super) fn required_notes_snapshot(&self, r: &Registry) -> Result<Option<notes_wire::StatusEnvelope>, BridgeError> {
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(edit_unknown()); }
        let projection = r.active.as_ref().map(|a| &a.projection).filter(|p| p.domain == EditDomain::RequiredNotes)
            .or_else(|| r.last.as_ref().filter(|p| p.domain == EditDomain::RequiredNotes));
        let result = projection.map(|p| p.required_notes_projection(r.revision)).transpose()?;
        wire::bounded(&result, notes_wire::STATUS_LIMIT)?;
        Ok(result)
    }
}

// A lost invoke can request STOP only for the actual ticket it claimed. It
// cannot stop a prior equal renderer request rejected before admission, nor
// infer finality, join workers, drop their handles or select a later session.
struct Caller<'a> {
    owner: &'a EditOwner, window: &'a str, project: String, binding: notes_wire::Binding,
    session: String, claimed: bool, completed: bool,
}
impl Drop for Caller<'_> {
    fn drop(&mut self) {
        if !self.claimed || self.completed { return; }
        let mut r = self.owner.inner.lock();
        if r.window.as_deref() != Some(self.window) { return; }
        let own = r.active.as_ref().is_some_and(|a|
            matches_original(&a.projection, &self.project, &self.binding, &self.session));
        if own { self.owner.inner.trigger_locked(&mut r, &self.session, Reason::CallerLost, Instant::now()); }
    }
}

impl EditOwner {
    pub(crate) fn required_notes_window(&self, window: &str) -> Result<String, BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || r.exhausted
            || self.inner.poisoned.load(Ordering::SeqCst) { return Err(invalid_owner()); }
        Ok(r.generation.clone())
    }
    pub(crate) fn required_notes_capability(&self) -> Capability {
        let r = self.inner.lock(); self.inner.capability(&r, EditDomain::RequiredNotes)
    }
    pub(crate) fn required_notes_latest_status(&self) -> Result<Option<notes_wire::StatusEnvelope>, BridgeError> {
        self.inner.required_notes_snapshot(&self.inner.lock())
    }
    pub(crate) fn required_notes_status(&self, window: &str, generation: &str, request: u32) -> Result<notes_wire::StatusEnvelope, BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || r.generation != generation
            || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) { return Err(invalid_owner()); }
        let projection = r.active.as_ref().map(|a| &a.projection).filter(|p| matches_request(p, generation, request, None))
            .or_else(|| r.last.as_ref().filter(|p| matches_request(p, generation, request, None)));
        // Null is unknown/unretained, never a receipt of no admission/cleanup.
        let reply = projection.map(|p| p.required_notes_projection(r.revision)).transpose()?
            .unwrap_or(notes_wire::StatusEnvelope { request_id: request, status: None });
        wire::bounded(&reply, notes_wire::STATUS_LIMIT)?; Ok(reply)
    }
    pub(crate) fn required_notes_project(&self, window: &str, generation: &str, request: u32, session: &str) -> Result<String, BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || r.generation != generation
            || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) { return Err(invalid_owner()); }
        r.active.as_ref().map(|a| &a.projection).filter(|p| matches_request(p, generation, request, Some(session)))
            .or_else(|| r.last.as_ref().filter(|p| matches_request(p, generation, request, Some(session))))
            .map(|p| p.project_id.clone()).ok_or_else(invalid_owner)
    }
    async fn required_notes_wait_phase(&self, window: &str, project: &str, binding: &notes_wire::Binding, session: &str, wanted: Phase) -> Result<(), BridgeError> {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable(); // Arm BEFORE taking the original snapshot.
            {
                let mut r = self.inner.lock();
                self.inner.expire_locked(&mut r, session, Instant::now());
                if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || r.generation != binding.window_generation
                    || r.disabled || r.exhausted || r.stopping || self.inner.poisoned.load(Ordering::SeqCst) { return Err(invalid_owner()); }
                let a = r.active.as_ref().filter(|a| matches_original(&a.projection, project, binding, session)).ok_or_else(invalid_owner)?;
                if a.cleanup_start.is_some() || a.unknown || a.projection.native_reason != Reason::None { return Err(invalid_owner()); }
                if a.projection.phase == wanted { return Ok(()); }
                if !matches!((wanted, a.projection.phase), (Phase::Editing, Phase::Opening) | (Phase::Reviewing, Phase::Preparing)) {
                    return Err(invalid_owner());
                }
            }
            changed.await;
        }
    }
    pub(crate) async fn prepare_required_notes_request(&self, document: &DocumentBinding, window: &str, args: commands::Prepare) -> Result<notes_wire::PreparedEnvelope, BridgeError> {
        let binding = args.binding();
        if !binding.valid() || self.required_notes_window(window)? != binding.window_generation { return Err(invalid_owner()); }
        let ticket = self.registered_open_ticket(window, EditDomain::RequiredNotes)?;
        let mut caller = Caller { owner: self, window, project: args.project_id.clone(), binding: binding.clone(),
            session: ticket.id.clone(), claimed: false, completed: false };
        let project = args.project_id.clone();
        let session = caller.session.clone();
        document.required_notes_edit_admit(|_| Ok(project.clone()), |bridge, registration| {
            if !Arc::ptr_eq(&bridge.edits.inner, &self.inner) { return Err(invalid_owner()); }
            bridge.edits.open_domain_attempt(window, project.clone(), registration.root.path.clone(), EditDomain::RequiredNotes,
                Some(registration), Some(ticket), None, None, Some(binding.clone()), &mut caller.claimed)?.required_notes()
        })?;
        self.required_notes_wait_phase(window, &project, &binding, &session, Phase::Editing).await?;
        document.required_notes_edit_admit(
            |bridge| bridge.edits.required_notes_project(window, &binding.window_generation, binding.request_id, &session),
            |bridge, registration| {
                let revision = {
                    let r = self.inner.lock();
                    let a = r.active.as_ref().filter(|a| matches_original(&a.projection, &project, &binding, &session)).ok_or_else(invalid_owner)?;
                    if a.session.registration.as_ref() != Some(&registration) { return Err(invalid_owner()); }
                    a.projection.revision().ok_or_else(invalid_owner)?.to_owned()
                };
                let params = json!({"revision":&revision,"context":&args.context,"expectedBaseline":&args.expected_baseline,"text":&args.text});
                let submission = notes_wire::Submission { context: args.context, expected_baseline: args.expected_baseline, text: args.text };
                bridge.edits.prepare_domain(window, EditDomain::RequiredNotes, &session, &revision, (binding.draft_revision, 0), params,
                    Some(registration), Some(SavedTextSubmission::RequiredNotes(submission)))?.required_notes()
            })?;
        self.required_notes_wait_phase(window, &project, &binding, &session, Phase::Reviewing).await?;
        // Original document/project registration is rechecked after the await,
        // before constructing the only private direct response.
        let prepared = document.required_notes_edit_admit(
            |bridge| bridge.edits.required_notes_project(window, &binding.window_generation, binding.request_id, &session),
            |_, registration| {
                let mut r = self.inner.lock(); self.inner.expire_locked(&mut r, &session, Instant::now());
                let a = r.active.as_ref().filter(|a| matches_original(&a.projection, &project, &binding, &session)).ok_or_else(invalid_owner)?;
                if a.session.registration.as_ref() != Some(&registration) || a.projection.phase != Phase::Reviewing || a.cleanup_start.is_some()
                    || a.unknown || a.projection.apply_submitted || a.projection.native_reason != Reason::None { return Err(invalid_owner()); }
                let detail = a.projection.required_notes.as_ref().ok_or_else(invalid_owner)?;
                let prepared = detail.prepared.as_ref().ok_or_else(invalid_owner)?;
                Ok(prepared.direct(&a.projection.project_id, &a.projection.owner_generation, &session, &binding))
            })?;
        caller.completed = true;
        Ok(notes_wire::PreparedEnvelope { request_id: binding.request_id, prepared })
    }
    pub(crate) fn apply_required_notes_request(&self, document: &DocumentBinding, window: &str, args: commands::Apply) -> Result<notes_wire::StatusEnvelope, BridgeError> {
        document.required_notes_edit_admit(
            |bridge| bridge.edits.required_notes_project(window, &args.window_generation, args.request_id, &args.session_id),
            |bridge, registration| {
                if !Arc::ptr_eq(&bridge.edits.inner, &self.inner) { return Err(invalid_owner()); }
                bridge.edits.apply_domain(window, EditDomain::RequiredNotes, &args.session_id, &args.plan_token, Some(registration))
            })?;
        self.required_notes_status(window, &args.window_generation, args.request_id)
    }
    pub(crate) fn close_required_notes_request(&self, window: &str, args: commands::Close) -> Result<notes_wire::StatusEnvelope, BridgeError> {
        {
            let r = self.inner.lock();
            // STOP needs the exact original binding, not healthy admission or
            // a successful status projection. Exhaustion/poison may refuse the
            // subsequent receipt but must not suppress this original STOP.
            // Document loss already STOPs and tombstones the old generation.
            if r.window.as_deref() != Some(window) || !r.document_bound || r.document_lost || r.generation != args.window_generation {
                return Err(invalid_owner());
            }
            let owns = r.active.as_ref().map(|a| &a.projection)
                .filter(|p| matches_request(p, &args.window_generation, args.request_id, Some(&args.session_id)))
                .or_else(|| r.last.as_ref().filter(|p| matches_request(p, &args.window_generation, args.request_id, Some(&args.session_id))));
            if owns.is_none() { return Err(invalid_owner()); }
        }
        self.close_domain(window, EditDomain::RequiredNotes, &args.session_id)?;
        self.required_notes_status(window, &args.window_generation, args.request_id)
    }
}

#[cfg(test)]
mod tests {
    // Original-request routing DATA only. No EditOwner constructor, RNG,
    // spawned task or native receipt is needed for these negative boundaries.
    use super::*;
    use notes_wire::tests::{projection, SESSION, WINDOW};
    #[test]
    fn request_id_never_substitutes_for_original_domain_window_session_project_or_draft() {
        let original=projection(); let binding=original.required_notes.as_ref().unwrap().binding.clone();
        assert!(matches_original(&original,"project-1",&binding,SESSION));
        assert!(!matches_request(&original,WINDOW,8,Some(SESSION)));
        assert!(!matches_request(&original,SESSION,7,Some(SESSION)));
        assert!(!matches_request(&original,WINDOW,7,Some(WINDOW)));
        assert!(!matches_original(&original,"project-2",&binding,SESSION));
        let mut changed=binding.clone(); changed.draft_revision+=1;
        assert!(!matches_original(&original,"project-1",&changed,SESSION));
        let mut changed=binding.clone(); changed.context=notes_wire::Context::IosBetaReview {};
        assert!(!matches_original(&original,"project-1",&changed,SESSION));
        for domain in [EditDomain::Configuration,EditDomain::GitHubWorkflows,EditDomain::MetadataText,EditDomain::ReleaseVersion,EditDomain::MetadataImages] {
            let mut changed=original.clone(); changed.domain=domain;
            assert!(!matches_request(&changed,WINDOW,7,Some(SESSION)));
        }
        let mut changed=original.clone(); changed.owner_generation=SESSION.into();
        assert!(!matches_original(&changed,"project-1",&binding,SESSION));
    }
    #[test]
    fn retiring_private_prepare_data_preserves_only_exact_original_stop_and_status_correlation() {
        let mut original=projection(); let binding=original.required_notes.as_ref().unwrap().binding.clone();
        original.required_notes.as_mut().unwrap().drop_private();
        original.phase=Phase::Unknown; original.native_finality=NativeFinality::Unknown;
        assert!(matches_original(&original,"project-1",&binding,SESSION));
        assert!(!matches_request(&original,WINDOW,6,Some(SESSION)));
        let row=original.required_notes_projection(19).ok().unwrap().status.unwrap();
        assert!(row.phase==Phase::Unknown && row.native_finality==NativeFinality::Unknown && !row.apply_submitted);
        assert_eq!(row.status_revision,19);
    }
}
