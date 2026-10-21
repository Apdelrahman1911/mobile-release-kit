//! Fixed recovery facet of the ORIGINAL SavedCommandOwner. No observation,
//! restore permit, task or native receipt is constructed from service DATA.
use super::*;
use crate::{
    agent_ios_archive::{self as agent, recovery as data},
    service_protocol as service,
};

fn failure() -> BridgeError {
    BridgeError::new("agent_ios_recovery_unavailable", "This original local iOS recovery request is unavailable. Inspect the original request; do not replay a restore.")
}
fn copy<T: serde::de::DeserializeOwned, V: serde::Serialize>(v: &V) -> Result<T, BridgeError> {
    serde_json::from_value(serde_json::to_value(v).map_err(|_| failure())?).map_err(|_| failure())
}
fn action(a: data::Action) -> ios_wire::RecoveryAction {
    match a {
        data::Action::Inspect => ios_wire::RecoveryAction::Inspect,
        data::Action::Account => ios_wire::RecoveryAction::Account,
        data::Action::Project => ios_wire::RecoveryAction::Project,
    }
}
fn context_matches(c: &ios_wire::Context, review: &data::Review) -> bool {
    c.recovery()
        && c.draft_revision.is_none()
        && c.baseline_generation.is_none()
        && c.saved_config.is_none()
        && c.saved_version.is_none()
        && c.signing.is_none()
        && c.action.is_none()
        && c.recovery.as_ref().is_some_and(|r| {
            r.action == action(review.recovery.action())
                && r.session.as_deref() == review.recovery.session()
        })
}
fn displayed(original: &IOSRecoveryObservation, selected: &data::Inspection) -> bool {
    original.original.id == selected.operation_id.as_str()
        && original.original.generation == selected.owner_generation.as_str()
}
/// Only the actual MAIN Allow path can construct this. It retains NO strong
/// Session/observation/resource graph. A later same-shaped report cannot replace
/// the displayed original, including when it contains the same session label.
pub(crate) struct Approval {
    owner: std::sync::Weak<Inner>,
    document: std::sync::Weak<()>,
    input: ios_wire::Prepare,
    review: data::Review,
    inspected: Option<std::sync::Weak<IOSRecoveryObservation>>,
}
impl Approval {
    pub(crate) fn input(&self) -> &ios_wire::Prepare {
        &self.input
    }
    pub(crate) fn review(&self) -> &data::Review {
        &self.review
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.input.project_id.capacity())?
            .checked_add(
                self.input
                    .recovery
                    .as_ref()
                    .and_then(|r| r.session.as_ref())
                    .map_or(0, String::capacity),
            )?
            .checked_add(self.review.recovery.heap_bytes()?)
            .and_then(|n| n.checked_add(3 * 2 * std::mem::size_of::<usize>()))
    }
    fn source_matches(
        &self,
        source: Option<&Arc<IOSRecoveryObservation>>,
        registration: u32,
        root: &RegisteredRoot,
    ) -> bool {
        match (&self.inspected, source, self.review.recovery.inspection()) {
            (None, None, None) => self.review.recovery.action() == data::Action::Inspect,
            (Some(weak), Some(source), Some(selected)) => {
                weak.as_ptr() == Arc::as_ptr(source)
                    && displayed(source, selected)
                    && source.matches(
                        &Context::IOSArchive(self.input.context()),
                        registration,
                        root,
                    )
            }
            _ => false,
        }
    }
    fn current(
        &self,
        inner: &Arc<Inner>,
        r: &Registry,
        registration: u32,
        root: &RegisteredRoot,
        bound: Option<&agent::NativeScope>,
    ) -> bool {
        if self.owner.as_ptr() != Arc::as_ptr(inner)
            || self.document.strong_count() == 0
            || !inner.ios_installed_selected()
        {
            return false;
        }
        if self.inspected.is_none() {
            return self.source_matches(None, registration, root);
        }
        if self.source_matches(r.recovery.as_ref(), registration, root) {
            return true;
        }
        // Start CONSUMES Registry.recovery. Only this same linked Prepared or
        // active Session may keep the approval current afterward. Requiring a
        // new current registry observation here would revoke our own restore.
        let Some(scope) = bound else {
            return false;
        };
        let same = |link: Option<&Arc<agent::NativeLink>>, context: &Context| {
            link.is_some_and(|l| std::ptr::eq(l.entry().scope(), scope))
                && context == &Context::IOSArchive(self.input.context())
        };
        r.prepared.as_ref().is_some_and(|p| {
            same(p.agent_build.as_ref(), &p.projection.context)
                && p.registration == registration
                && &p.project == root
                && self.source_matches(p.recovery.as_ref(), registration, root)
        }) || r.active.as_ref().is_some_and(|a| {
            same(a.owner.agent_build.as_ref(), &a.owner.context)
                && a.owner.registration == registration
                && &a.owner.project == root
                && self.source_matches(a.owner.recovery.as_ref(), registration, root)
        })
    }
}
pub(super) struct Preparation {
    pub(super) entry: Arc<agent::Entry>,
    pub(super) approval: Arc<Approval>,
}
fn same_context(
    entry: &agent::Entry,
    context: &Context,
    registration: u32,
    root: &RegisteredRoot,
) -> bool {
    let Context::IOSArchive(c) = context else {
        return false;
    };
    let s = entry.scope();
    let Some(review) = s.review.ios_recovery() else {
        return false;
    };
    matches!(s.input, crate::agent_build_requests::NativeInput::Recovery)
        && context_matches(c, review)
        && c.project_id == s.runtime_id
        && root.path == s.root
        && registration == s.registration
        && root
            .identity
            .posix()
            .is_ok_and(|i| i.service_identity() == (s.device, s.inode))
}
pub(super) fn prepare(
    input: Preparation,
    inner: &Arc<Inner>,
    r: &Registry,
    context: &Context,
    registration: u32,
    root: &RegisteredRoot,
    id: &str,
    generation: &str,
    revision: u32,
    expires: Instant,
) -> Result<Option<Arc<agent::NativeLink>>, BridgeError> {
    if !input.approval.current(inner, r, registration, root, None)
        || !std::sync::Weak::ptr_eq(&input.approval.document, &input.entry.scope().document)
        || &Context::IOSArchive(input.approval.input.context()) != context
        || Some(&input.approval.review) != input.entry.scope().review.ios_recovery()
        || !same_context(&input.entry, context, registration, root)
        || !input.entry.prepare_live()
    {
        return Err(failure());
    }
    input
        .entry
        .bind(
            agent::FAMILY,
            service::Id::parse(id).map_err(|_| failure())?,
            service::Id::parse(generation).map_err(|_| failure())?,
            revision,
            expires,
        )
        .map(Some)
        .map_err(|_| failure())
}
pub(super) fn start_matches(p: &Prepared, entry: Option<&Arc<agent::Entry>>) -> bool {
    match (&p.agent_build, entry) {
        (Some(link), Some(entry)) => {
            link.start_matches(agent::FAMILY, Some(entry))
                && link.matches(&p.projection.operation_id, &p.projection.owner_generation)
                && same_context(entry, &p.projection.context, p.registration, &p.project)
                && entry.scope().review.ios_recovery().is_some_and(|review| {
                    match review.recovery.inspection() {
                        None => p.recovery.is_none(),
                        Some(selected) => p.recovery.as_ref().is_some_and(|r| {
                            displayed(r, selected)
                                && r.matches(&p.projection.context, p.registration, &p.project)
                        }),
                    }
                })
        }
        (None, None) => true,
        _ => false,
    }
}
fn projection(
    link: &agent::NativeLink,
    p: &RunProjection,
    revision: u32,
    retired: bool,
) -> Result<data::Operation, BridgeError> {
    let Context::IOSArchive(c) = &p.context else {
        return Err(failure());
    };
    let review = link
        .entry()
        .scope()
        .review
        .ios_recovery()
        .ok_or_else(failure)?;
    if !context_matches(c, review) {
        return Err(failure());
    }
    let unknown = p.phase == Phase::Unknown;
    let (state, settlement, outcome, report) = if unknown {
        (
            service::OperationState::Unknown,
            service::Settlement::Unknown,
            Some(agent::Outcome::Unknown),
            None,
        )
    } else if retired {
        if p.phase != Phase::Terminal {
            return Err(failure());
        }
        let outcome: agent::Outcome = copy(&p.outcome.ok_or_else(failure)?.ios())?;
        let state = match outcome {
            agent::Outcome::Complete => service::OperationState::Succeeded,
            agent::Outcome::Cancelled => service::OperationState::Cancelled,
            agent::Outcome::Refused | agent::Outcome::Failed | agent::Outcome::TimedOut => {
                service::OperationState::Failed
            }
            agent::Outcome::Unknown => return Err(failure()),
        };
        let report = match &p.result {
            Some(Terminal::IOSArchive(t)) if t.context == *c && t.settled() => {
                t.report.as_ref().map(copy).transpose()?
            }
            None if outcome != agent::Outcome::Complete => None,
            _ => return Err(failure()),
        };
        (state, service::Settlement::Settled, Some(outcome), report)
    } else {
        let state = match p.phase {
            Phase::AwaitingConsent => service::OperationState::Prepared,
            Phase::Starting | Phase::Running => service::OperationState::Running,
            Phase::Stopping => service::OperationState::CancellationRequested,
            _ => return Err(failure()),
        };
        (state, service::Settlement::Pending, None, None)
    };
    let result = data::Operation {
        operation_id: service::Id::parse(&p.operation_id).map_err(|_| failure())?,
        owner_generation: service::Id::parse(&p.owner_generation).map_err(|_| failure())?,
        status_revision: revision,
        state,
        settlement,
        outcome,
        reason: if unknown {
            data::Reason::CleanupUnknown
        } else {
            copy(&p.reason.ios()?)?
        },
        stage: if unknown {
            None
        } else {
            match p.stage {
                None => None,
                Some(Stage::IOSArchive(s)) => Some(copy(&s)?),
                _ => return Err(failure()),
            }
        },
        report,
    };
    if !result.valid_for(review) {
        return Err(failure());
    }
    Ok(result)
}
fn publish(link: &agent::NativeLink, p: &RunProjection, revision: u32, retired: bool) {
    if projection(link, p, revision, retired)
        .and_then(|p| link.publish(p).map_err(|_| failure()))
        .is_err()
    {
        link.entry().unconfirmed();
    }
}
pub(super) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if let Some(link) = &a.owner.agent_build {
            publish(link, &a.projection, r.revision, false);
        }
    } else if let Some(p) = &r.prepared {
        if let Some(link) = &p.agent_build {
            publish(link, &p.projection, r.revision, false);
        }
    }
}
pub(super) fn retired_prepared(p: &Prepared, reason: Reason, revision: u32) {
    if let Some(link) = &p.agent_build {
        publish(link, &retire(p.projection.clone(), reason), revision, true);
    }
}
pub(super) fn retired(a: &Active, revision: u32) {
    if let Some(link) = &a.owner.agent_build {
        publish(link, &a.projection, revision, true);
    }
}

impl SavedCommandOwner {
    pub(crate) fn approve_agent_ios_recovery(
        &self,
        project_id: String,
        selected: data::Selection,
        document: &Arc<()>,
        registration: u32,
        root: &RegisteredRoot,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        let r = self.inner.lock();
        let source = match selected.inspection() {
            None => None,
            Some(display) => Some(
                r.recovery
                    .as_ref()
                    .filter(|o| displayed(o, display))
                    .ok_or_else(failure)?,
            ),
        };
        let session = match (&selected, source) {
            (data::Selection::Inspect, None) => None,
            (data::Selection::Account { .. }, Some(o)) => o
                .terminal
                .report
                .as_ref()
                .and_then(|r| r.account.as_ref())
                .and_then(|r| r.session.clone()),
            (data::Selection::Project { .. }, Some(o)) => o
                .terminal
                .report
                .as_ref()
                .and_then(|r| r.project.as_ref())
                .and_then(|r| r.session.clone()),
            _ => return Err(failure()),
        };
        let recovery = ios_wire::RecoveryIntent {
            action: action(selected.action()),
            session,
        };
        let input =
            ios_wire::prepare(&serde_json::json!({"projectId":project_id,"recovery":&recovery}))?;
        let intent = match selected {
            data::Selection::Inspect => data::Intent::Inspect,
            data::Selection::Account { inspection } => data::Intent::Account {
                inspection,
                session: recovery.session.clone().ok_or_else(failure)?,
            },
            data::Selection::Project { inspection } => data::Intent::Project {
                inspection,
                session: recovery.session.clone().ok_or_else(failure)?,
            },
        };
        let approval = Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            document: Arc::downgrade(document),
            input,
            review: data::Review {
                mode: data::Mode::LocalIosRecovery,
                recovery: intent,
            },
            inspected: source.map(Arc::downgrade),
        });
        if !approval.review.capacity_valid()
            || !approval.source_matches(source, registration, root)
            || !self
                .inner
                .ios_mode_qualified(&Context::IOSArchive(approval.input.context()), None)
            || self.inner.availability(&r, Availability::Available) != Availability::Available
            || !approval.current(&self.inner, &r, registration, root, None)
        {
            return Err(failure());
        }
        Ok(approval)
    }
    pub(crate) fn agent_ios_recovery_approval_current(
        &self,
        approval: &Approval,
        document: &Arc<()>,
        scope: &agent::NativeScope,
        registration: u32,
        root: &RegisteredRoot,
    ) -> bool {
        self.inner.domain == SavedCommandDomain::IOSArchive
            && approval.document.as_ptr() == Arc::as_ptr(document)
            && approval.current(
                &self.inner,
                &self.inner.lock(),
                registration,
                root,
                Some(scope),
            )
    }
    pub(crate) fn prepare_agent_ios_recovery(
        &self,
        entry: Arc<agent::Entry>,
        approval: Arc<Approval>,
        registration: u32,
        root: RegisteredRoot,
        gate: ios_wire::Availability,
    ) -> Result<ios_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.prepare_bound_requests(
            Context::IOSArchive(approval.input.context()),
            registration,
            root,
            Availability::from_ios(gate),
            None,
            None,
            None,
            Some(agent_build::Preparation::IosRecovery(Preparation {
                entry,
                approval,
            })),
        )?
        .ios()
    }
    pub(crate) fn start_agent_ios_recovery(
        &self,
        entry: &Arc<agent::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: ios_wire::Availability,
    ) -> Result<crate::ios_archive_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        let input = {
            let r = self.inner.lock();
            let p = r
                .prepared
                .as_ref()
                .filter(|p| start_matches(p, Some(entry)))
                .ok_or_else(failure)?;
            Start {
                operation_id: p.projection.operation_id.clone(),
                owner_generation: p.projection.owner_generation.clone(),
            }
        };
        let a = self.start_bound_requests(
            input,
            entry.start_at().ok_or_else(failure)?,
            registered,
            Availability::from_ios(gate),
            None,
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(crate::ios_archive_owner::Admitted::new(
            a.status.ios()?,
            a.release,
        ))
    }
    /// Current original native inspection AND same Entry's acknowledged final
    /// metadata. A terminal event/consumed permission alone supplies neither.
    pub(crate) fn agent_ios_recovery_acknowledged(
        &self,
        document: &Arc<()>,
    ) -> Option<data::AcknowledgedInspection> {
        let r = self.inner.lock();
        let o = r.recovery.as_ref()?;
        let link = o.original.agent_build.as_ref()?;
        if link.entry().scope().document.as_ptr() != Arc::as_ptr(document)
            || !link
                .entry()
                .scope()
                .review
                .ios_recovery()
                .is_some_and(|v| v.recovery.action() == data::Action::Inspect)
        {
            return None;
        }
        let row = link.entry().catalogue_metadata().ok()?;
        let op = row.operation.as_ref()?;
        if !row.history_available
            || op.settlement != service::Settlement::Settled
            || op.operation_id.as_str() != o.original.id
            || op.owner_generation.as_str() != o.original.generation
            || !matches!(
                row.progress,
                crate::service_request_catalogue::Progress::IosArchive {
                    request_state: crate::agent_build_requests::RequestState::OriginalAvailable,
                    start_state: crate::agent_build_requests::StartState::Consumed
                }
            )
        {
            return None;
        }
        Some(data::AcknowledgedInspection {
            origin: link.origin(),
            inspection: data::Inspection {
                operation_id: op.operation_id.clone(),
                owner_generation: op.owner_generation.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{active_with_context, recovery_terminal_data};
    use super::*;

    fn owner() -> SavedCommandOwner {
        SavedCommandOwner::ios_archive(RuntimeConfig::packaged(
            "/unopened-ios-recovery-runtime".into(),
        ))
    }
    fn inspected() -> (SavedCommandOwner, Arc<IOSRecoveryObservation>) {
        let (app, original) = active_with_context(
            owner(),
            Context::IOSArchive(ios_wire::tests::recovery_context()),
        );
        (
            app,
            Arc::new(IOSRecoveryObservation {
                original,
                terminal: recovery_terminal_data(),
            }),
        )
    }
    fn approval(
        app: &SavedCommandOwner,
        document: &Arc<()>,
        observation: &Arc<IOSRecoveryObservation>,
    ) -> Approval {
        let inspection = data::Inspection {
            operation_id: service::Id::parse(&observation.original.id).unwrap(),
            owner_generation: service::Id::parse(&observation.original.generation).unwrap(),
        };
        Approval {
            owner: Arc::downgrade(&app.inner),
            document: Arc::downgrade(document),
            input: ios_wire::prepare(&serde_json::json!({"projectId":"inert-ios",
                "recovery":{"action":"account","session":"c".repeat(32)}}))
            .unwrap(),
            review: data::Review {
                mode: data::Mode::LocalIosRecovery,
                recovery: data::Intent::Account {
                    inspection,
                    session: "c".repeat(32),
                },
            },
            inspected: Some(Arc::downgrade(observation)),
        }
    }
    // These use the original constructor-only Saved fixture. The explicit
    // flags below are predicate DATA, never an executed native join/receipt.
    #[test]
    fn recovery_approval_keeps_exact_displayed_weak_observation_and_original_join_predicate() {
        let (app, original) = inspected();
        let document = Arc::new(());
        let mut approval = approval(&app, &document, &original);
        let root = original.original.project.clone();
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(!approval.source_matches(Some(&original), 1, &root));
        original
            .original
            .watchdog_joined
            .store(true, Ordering::SeqCst);
        *original.original.watchdog_return.lock().unwrap() = Some(Ok(true));
        assert!(approval.source_matches(Some(&original), 1, &root));
        let same_data = Arc::new(IOSRecoveryObservation {
            original: original.original.clone(),
            terminal: recovery_terminal_data(),
        });
        assert!(!approval.source_matches(Some(&same_data), 1, &root));
        assert!(!approval.source_matches(Some(&original), 2, &root));
        let mut foreign = root.clone();
        foreign.path.push("different");
        assert!(!approval.source_matches(Some(&original), 1, &foreign));
        let data::Intent::Account { inspection, .. } = &mut approval.review.recovery else {
            panic!("account fixture")
        };
        inspection.operation_id = service::Id::parse(&"f".repeat(32)).unwrap();
        assert!(!approval.source_matches(Some(&original), 1, &root));
        let weak = approval.inspected.as_ref().unwrap().clone();
        drop(original);
        assert!(weak.upgrade().is_none()); // neither approval nor old report retains it
        assert!(
            approval.retained_bytes().unwrap()
                <= crate::agent_build_requests::RECOVERY_BINDING_BYTES
        );
        assert!(app.agent_ios_recovery_acknowledged(&document).is_none());
    }
    #[test]
    fn recovery_approval_refuses_lost_custody_and_no_source_grants_no_restore() {
        let (app, original) = inspected();
        let document = Arc::new(());
        let a = approval(&app, &document, &original);
        let root = original.original.project.clone();
        original
            .original
            .watchdog_joined
            .store(true, Ordering::SeqCst);
        *original.original.watchdog_return.lock().unwrap() = Some(Ok(true));
        assert!(a.source_matches(Some(&original), 1, &root));
        assert!(!a.source_matches(None, 1, &root));
        original
            .original
            .material_retired
            .store(false, Ordering::SeqCst);
        assert!(!a.source_matches(Some(&original), 1, &root));
        original
            .original
            .material_retired
            .store(true, Ordering::SeqCst);
        original
            .original
            .resource_unknown
            .store(true, Ordering::SeqCst);
        assert!(!a.source_matches(Some(&original), 1, &root));
        original
            .original
            .resource_unknown
            .store(false, Ordering::SeqCst);
        *original.original.watchdog_return.lock().unwrap() = Some(Ok(false));
        assert!(!a.source_matches(Some(&original), 1, &root));
        // Actual MAIN approval still checks installed-runtime nomination. The
        // fixture cannot turn any of the above DATA into a production grant.
        let selected = a.review.recovery.selection();
        assert!(app
            .approve_agent_ios_recovery("inert-ios".into(), selected, &document, 1, &root)
            .is_err());
        assert!(app.inner.lock().prepared.is_none());
    }
    #[test]
    fn recovery_common_start_requires_same_link_and_read_before_consuming_configless_intent() {
        let app = owner();
        let document = Arc::new(());
        let id = |c: char| service::Id::parse(&c.to_string().repeat(32)).unwrap();
        let root = RegisteredRoot {
            path: "/inert/never-opened".into(),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let (device, inode) = root.identity.posix().unwrap().service_identity();
        let input = ios_wire::prepare(
            &serde_json::json!({"projectId":"inert-ios","recovery":{"action":"inspect"}}),
        )
        .unwrap();
        let read = Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                Instant::now() + Duration::from_secs(600),
            ),
        );
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(agent::NativeScope {
            project_id: id('c'),
            runtime_id: "inert-ios".into(),
            root: root.path.clone(),
            device,
            inode,
            registration: 1,
            input_revision: 0,
            document: Arc::downgrade(&document),
            observation_revision: 2,
            input: crate::agent_build_requests::NativeInput::Recovery,
            read: Some(read.clone()),
            changes,
            review: data::Review {
                mode: data::Mode::LocalIosRecovery,
                recovery: data::Intent::Inspect,
            }
            .into(),
        });
        let point = crate::agent_local_checks::SavedPoint {
            project_id: id('c'),
            runtime_id: scope.runtime_id.clone(),
            root: scope.root.clone(),
            device,
            inode,
            revision: 2,
            fresh: true,
            config: None,
        };
        let inbox = agent::Inbox::new(id('e'));
        inbox.allow(scope).unwrap();
        let request = agent::Prepare {
            service_instance: id('e'),
            project_id: id('c'),
            request_id: id('f'),
            expected_observation_revision: 2,
        };
        inbox
            .prepare_ios_read(request.clone(), &point, &read)
            .unwrap();
        let preparing = inbox.claim(agent::FAMILY).unwrap().unwrap();
        let expires = Instant::now() + INTENT;
        let link = preparing
            .entry()
            .bind(agent::FAMILY, id('a'), id('b'), 1, expires)
            .unwrap();
        let prepared = Prepared {
            agent_history: None,
            agent_store_preparation: None,
            agent_store: None,
            store_witness: None,
            agent_build: Some(link.clone()),
            agent_local_check: None,
            upload_key_preparation: None,
            upload_key: None,
            apple: None,
            tools: None,
            local_history: None,
            expires,
            registration: 1,
            project: root.clone(),
            recovery_stamp: None,
            material: None,
            recovery: None,
            android_selection: None,
            artifact_selection: None,
            artifact_tools: None,
            projection: RunProjection {
                agent_build: Some(link.projection_origin()),
                agent_local_check: None,
                operation_id: "a".repeat(32),
                owner_generation: "b".repeat(32),
                context: Context::IOSArchive(input.context()),
                phase: Phase::AwaitingConsent,
                intent_usable: true,
                outcome: None,
                reason: Reason::None,
                result: None,
                stage: None,
            },
        };
        assert!(!agent_build::start_matches(&prepared, None));
        {
            let mut r = app.inner.lock();
            r.revision = 1;
            r.prepared = Some(prepared);
        }
        let gui = ios_wire::start(
            &serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
            "consentVersion":ios_wire::RECOVERY_CONSENT}),
        )
        .unwrap();
        assert!(app
            .start_ios(
                gui,
                Instant::now(),
                Some((1, root.clone())),
                ios_wire::Availability::RuntimeUnqualified
            )
            .is_err());
        assert!(app.inner.lock().prepared.is_some());
        preparing.returned(true);
        let (_, prepared_data) = link.entry().claim_history().unwrap().unwrap();
        link.entry()
            .history_returned(prepared_data.status_revision(), Ok(()))
            .unwrap();
        let start = agent::Start {
            origin: request.query(),
            operation_id: id('a'),
            owner_generation: id('b'),
        };
        inbox.start_ios_read(&start, &point, &read).unwrap();
        let starting = inbox.claim(agent::FAMILY).unwrap().unwrap();
        {
            let mut r = app.inner.lock();
            let Context::IOSArchive(c) = &mut r.prepared.as_mut().unwrap().projection.context
            else {
                panic!("iOS")
            };
            c.project_id = "different".into();
        }
        assert!(app
            .start_agent_ios_recovery(
                starting.entry(),
                Some((1, root.clone())),
                ios_wire::Availability::RuntimeUnqualified
            )
            .is_err());
        assert!(app.inner.lock().prepared.is_some());
        {
            let mut r = app.inner.lock();
            r.prepared.as_mut().unwrap().projection.context = Context::IOSArchive(input.context());
        }
        let returned = app
            .start_agent_ios_recovery(
                starting.entry(),
                Some((1, root)),
                ios_wire::Availability::RuntimeUnqualified,
            )
            .unwrap()
            .release();
        assert_eq!(
            returned.operation.unwrap().outcome,
            Some(ios_wire::Outcome::Refused)
        );
        {
            let r = app.inner.lock();
            assert!(r.prepared.is_none() && r.active.is_none());
        }
        assert_eq!(
            starting.entry().status().unwrap().start_state,
            agent::StartState::Consumed
        );
        assert!(link.entry().claim_history().unwrap().is_none()); // native refusal did not return the caller
        starting.returned(true);
        assert!(link.entry().claim_history().unwrap().is_some());
        // No runtime open/spawn/GO was reached and no native join was invented.
    }
}
