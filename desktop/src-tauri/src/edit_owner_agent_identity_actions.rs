//! Closed CLI facet INSIDE the original identity link/EditOwner. No new
//! Session, worker, source reader, timer, cleanup owner or history publisher.
use super::*;
use requests::actions::{self as action, Kind};

pub(crate) struct ActionApproval {
    entry: Arc<requests::Entry>,
    session: Weak<Session>,
    status_revision: u32,
    checkout: Id,
}
fn current<'a>(
    inner: &Arc<Inner>,
    r: &'a Registry,
    window: &str,
    entry: &Arc<requests::Entry>,
    registered: &RegisteredEditRoot,
    continuity: identity_wire::NativeContinuity,
) -> Result<&'a ActiveOwner, BridgeError> {
    inner.admission(r, window, EditDomain::ProjectIdentity)?;
    let a = r.active.as_ref().ok_or_else(invalid_owner)?;
    let link = a
        .session
        .agent_identity
        .as_ref()
        .ok_or_else(invalid_owner)?;
    if !Arc::ptr_eq(&link.entry, entry)
        || link.owner.as_ptr() != Arc::as_ptr(inner)
        || !link.active(a)
        || &link.registered != registered
        || !entry.review_live(Instant::now())
        || a.cleanup_start.is_some()
        || a.unknown
        || a.terminal
        || *a.session.stop.borrow()
        || a.projection.native_finality != NativeFinality::Pending
        || !a
            .projection
            .identity
            .as_ref()
            .is_some_and(|d| d.accepts_current_continuity(continuity))
    {
        return Err(invalid_owner());
    }
    Ok(a)
}
fn editable(a: &ActiveOwner, entry: &requests::Entry, revision: &str) -> bool {
    let Some(detail) = a.projection.identity.as_ref() else {
        return false;
    };
    let change = &entry.input().change;
    let mut probe = detail.clone();
    a.opened
        && !a.prepared
        && !a.projection.apply_submitted
        && a.projection.phase == Phase::Editing
        && a.prepare_counters.is_none()
        && a.claimed_seq == 0
        && a.projection.revision() == Some(revision)
        && detail.intent == identity_wire::Intent::Edit
        && probe.admit_submission(identity_wire::Submission::Edit {
            desired_identity: change.desired_identity.clone(),
            identity_intent: intent(change.identity_intent),
        })
}
impl EditOwner {
    /// A retained old intent cannot cancel a replacement review. The per-entry
    /// latch also prevents a pending Allow from granting after this request.
    pub(crate) fn cancel_identity_action(
        &self,
        window: &str,
        entry: &Arc<requests::Entry>,
    ) -> Result<(), BridgeError> {
        let mut publication = self.inner.mandatory_publication();
        let result = (|| {
            let mut r = self.inner.lock();
            if r.window.as_deref() != Some(window) || r.document_lost {
                return Err(invalid_owner());
            }
            let at = Instant::now();
            entry.cancel_action(at);
            if let Some(a) = r.active.as_ref().filter(|a| {
                a.session
                    .agent_identity
                    .as_ref()
                    .is_some_and(|link| Arc::ptr_eq(&link.entry, entry) && link.active(a))
            }) {
                let id = a.session.id.clone();
                self.inner.expire_locked(&mut publication, &mut r, &id, at);
                self.inner
                    .trigger_locked(&mut publication, &mut r, &id, Reason::Cancelled, at);
            }
            Ok(())
        })();
        publication.finish();
        result
    }
    pub(crate) fn capture_identity_action(
        &self,
        window: &str,
        entry: Arc<requests::Entry>,
        session: &str,
        revision: &str,
        acknowledged: bool,
        registered: &RegisteredEditRoot,
        continuity: identity_wire::NativeContinuity,
    ) -> Result<ActionApproval, BridgeError> {
        let r = self.inner.lock();
        let a = current(&self.inner, &r, window, &entry, registered, continuity)?;
        if a.session.id != session
            || entry.actions().is_some()
            || !editable(a, &entry, revision)
            || entry.input().change.identity_intent == requests::IdentityIntent::NewApplication
                && !acknowledged
        {
            return Err(invalid_owner());
        }
        Ok(ActionApproval {
            entry,
            session: Arc::downgrade(&a.session),
            status_revision: r.revision,
            checkout: Id::parse(revision).map_err(|_| invalid_owner())?,
        })
    }
    /// After the original off-Doc Host/service/root comparison. Equal-looking
    /// replacement projections are insufficient: the SAME Session is retained.
    pub(crate) fn allow_identity_action(
        &self,
        window: &str,
        approval: ActionApproval,
        registered: &RegisteredEditRoot,
        continuity: identity_wire::NativeContinuity,
    ) -> Result<action::Status, BridgeError> {
        let r = self.inner.lock();
        let entry = &approval.entry;
        let a = current(&self.inner, &r, window, entry, registered, continuity)?;
        if approval.status_revision != r.revision
            || approval.session.as_ptr() != Arc::as_ptr(&a.session)
            || !editable(a, entry, approval.checkout.as_str())
        {
            return Err(invalid_owner());
        }
        let link = a.session.agent_identity.as_ref().unwrap();
        entry
            .allow_actions(
                action::Original {
                    operation_id: link.operation.clone(),
                    owner_generation: link.generation.clone(),
                    revision: approval.checkout,
                },
                a.review_end,
                a.session.stop.clone(),
            )
            .map_err(|_| invalid_owner())?;
        publish(&a.session, &a.projection, a.unknown, r.revision, false);
        entry.action_status().map_err(|_| invalid_owner())
    }
    pub(crate) fn prepare_identity_action_published(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        entry: Arc<requests::Entry>,
        registered: RegisteredEditRoot,
        continuity: identity_wire::NativeContinuity,
    ) -> Result<IdentityStatus, BridgeError> {
        let original = entry
            .actions()
            .ok_or_else(invalid_owner)?
            .original()
            .clone();
        self.recheck_identity_continuity(
            publisher,
            window,
            original.operation_id.as_str(),
            continuity,
        )?;
        let change = &entry.input().change;
        let args = identity_wire::Prepare::Edit {
            session_id: original.operation_id.as_str().to_owned(),
            revision: original.revision.as_str().to_owned(),
            desired_identity: change.desired_identity.clone(),
            identity_intent: intent(change.identity_intent),
        };
        self.prepare_domain_action(
            Some(publisher),
            window,
            EditDomain::ProjectIdentity,
            args.session_id(),
            args.revision(),
            (0, 0),
            args.params(),
            Some(registered),
            Some(SavedTextSubmission::Identity(args.submission())),
            Some(&entry),
        )?
        .identity()
    }
    pub(crate) fn start_identity_action_published(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        entry: Arc<requests::Entry>,
        registered: RegisteredEditRoot,
        continuity: identity_wire::NativeContinuity,
    ) -> Result<IdentityStatus, BridgeError> {
        let original = entry
            .actions()
            .ok_or_else(invalid_owner)?
            .original()
            .clone();
        self.recheck_identity_continuity(
            publisher,
            window,
            original.operation_id.as_str(),
            continuity,
        )?;
        let plan = entry
            .actions()
            .ok_or_else(invalid_owner)?
            .retained_plan()
            .map_err(|_| invalid_owner())?;
        // The native link/checkout are rechecked at the SAME existing Apply
        // claim; DTO IDs never confer authority on a replacement session.
        self.apply_domain_action(
            Some(publisher),
            window,
            EditDomain::ProjectIdentity,
            original.operation_id.as_str(),
            plan.as_str(),
            Some(registered),
            false,
            Some(&entry),
        )?
        .identity()
    }
}
pub(in crate::edit_owner) fn allowed(
    a: &ActiveOwner,
    entry: Option<&Arc<requests::Entry>>,
    kind: Kind,
) -> bool {
    match (a.session.agent_identity.as_ref(), entry) {
        (None, None) => true,
        (Some(link), None) => link.entry.actions().is_none(), // A GUI click cannot consume delegated work.
        (Some(link), Some(entry)) => {
            Arc::ptr_eq(entry, &link.entry)
                && link.active(a)
                && entry.action_admitting(kind)
                && entry.actions().is_some_and(|s| {
                    a.projection.revision() == Some(s.original().revision.as_str())
                })
        }
        _ => false,
    }
}
pub(in crate::edit_owner) fn consume(
    a: &ActiveOwner,
    entry: Option<&Arc<requests::Entry>>,
    kind: Kind,
) -> bool {
    allowed(a, entry, kind) && entry.is_none_or(|e| e.consume_action(kind).is_ok())
}
pub(in crate::edit_owner) fn cancellation_at(
    session: &Session,
    now: Instant,
) -> Option<(Instant, Reason)> {
    session
        .agent_identity
        .as_ref()?
        .entry
        .actions()?
        .cancellation_at(now)
        .map(|(at, expired)| {
            (
                at,
                if expired {
                    Reason::ReviewExpired
                } else {
                    Reason::Cancelled
                },
            )
        })
}
fn review(p: &EditProjection) -> Result<Option<action::Review>, BridgeError> {
    let detail = p
        .identity
        .as_ref()
        .filter(|d| d.valid())
        .ok_or_else(invalid_owner)?;
    let Some(prepared) = &detail.prepared else {
        return Ok(None);
    };
    let view = &prepared.view;
    let before = detail
        .checkout
        .as_ref()
        .and_then(|c| c.view["identity"].as_str())
        .ok_or_else(invalid_owner)?;
    let rows = view["changes"].as_array().ok_or_else(invalid_owner)?;
    let changes = rows
        .iter()
        .map(|r| {
            Ok(action::Location {
                path: r["path"].as_str().ok_or_else(invalid_owner)?.to_owned(),
                line: r["line"]
                    .as_u64()
                    .and_then(|n| n.try_into().ok())
                    .ok_or_else(invalid_owner)?,
                column: r["column"]
                    .as_u64()
                    .and_then(|n| n.try_into().ok())
                    .ok_or_else(invalid_owner)?,
                role: match r["role"].as_str() {
                    Some("saved-identity") => action::Role::SavedIdentity,
                    Some("android-application-id") => action::Role::AndroidApplicationId,
                    Some("ios-bundle-id") => action::Role::IosBundleId,
                    _ => return Err(invalid_owner()),
                },
            })
        })
        .collect::<Result<Vec<_>, BridgeError>>()?;
    let unchanged = view["state"] == "unchanged";
    let after = if unchanged {
        before
    } else {
        rows.first()
            .and_then(|r| r["afterId"].as_str())
            .ok_or_else(invalid_owner)?
    };
    Ok(Some(action::Review {
        plan_token: Id::parse(&prepared.plan_token).map_err(|_| invalid_owner())?,
        before_identity: before.to_owned(),
        after_identity: after.to_owned(),
        changes,
        unchanged,
        new_application_warning: !unchanged,
        build_verification_required: view["buildVerificationRequired"] == true,
        retain_version_reservations: view["retainVersionReservations"] == true,
    }))
}
fn publish(
    session: &Arc<Session>,
    p: &EditProjection,
    unknown: bool,
    revision: u32,
    retired: bool,
) {
    let Some(link) = session
        .agent_identity
        .as_ref()
        .filter(|l| l.entry.actions().is_some())
    else {
        return;
    };
    let result = (|| {
        if link
            .session
            .get()
            .is_none_or(|s| s.as_ptr() != Arc::as_ptr(session))
            || p.session_id != session.id
            || p.owner_generation != link.generation.as_str()
            || p.domain != EditDomain::ProjectIdentity
            || p.project_id != link.entry.scope().runtime_id
        {
            return Err(invalid_owner());
        }
        // Reuse the already reviewed exact ORIGINAL retirement mapper. This
        // does not publish history twice or treat a terminal frame as a join.
        use crate::application_service_host::IdentityObservation as O;
        use crate::service_protocol::{OperationState as S, Settlement as F};
        let (state, settlement) = match identity_history::observation(p, unknown, retired)
            .map_err(|_| invalid_owner())?
        {
            O::Running => (S::Running, F::Pending),
            O::Prepared => (S::Prepared, F::Pending),
            O::CancellationRequested => (S::CancellationRequested, F::Pending),
            O::Succeeded => (S::Succeeded, F::Settled),
            O::Failed => (S::Failed, F::Settled),
            O::Cancelled => (S::Cancelled, F::Settled),
            O::RecoveryRequired => (S::RecoveryRequired, F::Settled),
            O::Unknown => (S::Unknown, F::Unknown),
        };
        let effect = p.core_outcome.as_ref().map(|c| match c.effect {
            Effect::NotStarted => action::Effect::NotStarted,
            Effect::Unchanged => action::Effect::Unchanged,
            Effect::Committed => action::Effect::Committed,
            Effect::RolledBack => action::Effect::RolledBack,
            Effect::Unknown => action::Effect::Unknown,
        });
        let journal = p.core_outcome.as_ref().map(|c| match c.journal {
            Journal::NotCreated => action::Journal::NotCreated,
            Journal::Clean => action::Journal::Clean,
            Journal::RecoveryRequired => action::Journal::RecoveryRequired,
            Journal::Unknown => action::Journal::Unknown,
        });
        link.entry
            .observe_action(action::Observation {
                status_revision: revision,
                state,
                settlement,
                apply_submitted: p.apply_submitted,
                review: review(p)?,
                effect,
                journal,
            })
            .map_err(|_| invalid_owner())
    })();
    if result.is_err() {
        link.entry.action_unconfirmed();
    }
}
pub(in crate::edit_owner) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        publish(&a.session, &a.projection, a.unknown, r.revision, false);
    }
}
pub(in crate::edit_owner) fn retired(r: &Registry, session: &Arc<Session>, unknown: bool) {
    if let Some(p) = &r.last {
        publish(session, p, unknown, r.revision, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unopened_owner_does_not_invent_an_action_approval() {
        let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/inert-identity-action",
        )));
        assert!(owner.identity_open_ticket("main").is_err());
        assert!(owner.inner.lock().active.is_none());
    }
    fn projection(prepared: bool, unchanged: bool) -> EditProjection {
        EditProjection {
            domain: EditDomain::ProjectIdentity,
            identity: Some(identity_wire::tests::edit_details(prepared, unchanged)),
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            project_id: "project-1".into(),
            session_id: "1".repeat(32),
            owner_generation: "2".repeat(32),
            phase: Phase::Reviewing,
            review_remaining_ms: 1,
            checkout: None,
            prepared: None,
            recovery: None,
            apply_submitted: false,
            core_outcome: None,
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    #[test]
    fn compact_preview_comes_from_exact_existing_identity_details() {
        for unchanged in [false, true] {
            let p = projection(true, unchanged);
            let value = review(&p).unwrap().unwrap();
            assert_eq!(value.unchanged, unchanged);
            assert_eq!(value.new_application_warning, !unchanged);
            assert!(value.build_verification_required && value.retain_version_reservations);
            assert_eq!(value.changes.is_empty(), unchanged);
            let change = requests::Change {
                selection: requests::Selection {
                    platform: requests::Platform::Android,
                    target: ":app".into(),
                    project: None,
                },
                desired_identity: value.after_identity.clone(),
                identity_intent: requests::IdentityIntent::NewApplication,
            };
            assert!(value.valid(&change));
        }
        assert!(review(&projection(false, false)).unwrap().is_none());
        let mut malformed = projection(true, false);
        malformed
            .identity
            .as_mut()
            .unwrap()
            .prepared
            .as_mut()
            .unwrap()
            .view["changes"][0]["path"] = serde_json::json!("/private/key");
        assert!(review(&malformed).is_err());
    }
    #[test]
    fn actual_core_frame_and_close_are_not_delegated_apply_success() {
        let mut p = projection(true, false);
        p.phase = Phase::Finalizing;
        p.apply_submitted = true;
        p.core_outcome = Some(wire::CoreEditOutcome {
            effect: Effect::Committed,
            journal: Journal::Clean,
            resources: ResourceState::Settled,
            reason: CoreReason::None,
        });
        use crate::application_service_host::IdentityObservation as O;
        assert_eq!(
            identity_history::observation(&p, false, false),
            Ok(O::Running)
        );
        assert!(identity_history::observation(&p, false, true).is_err());
        p.phase = Phase::Final;
        p.native_finality = NativeFinality::Settled;
        assert_eq!(
            identity_history::observation(&p, false, true),
            Ok(O::Succeeded)
        );
        p.native_reason = Reason::Cancelled;
        assert_eq!(
            identity_history::observation(&p, false, true),
            Ok(O::Failed)
        );
        p.native_finality = NativeFinality::Unknown;
        assert_eq!(
            identity_history::observation(&p, true, true),
            Ok(O::Unknown)
        );
    }
}
