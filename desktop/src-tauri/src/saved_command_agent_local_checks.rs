//! Closed adapter INSIDE the original SavedCommandOwner. No runner, observer
//! or status-shaped native receipt is introduced for a CLI request.
use super::*;
use crate::{agent_local_checks as agent, service_protocol as service};

fn failure() -> BridgeError {
    BridgeError::new("agent_local_check_unavailable","The original local-check request cannot be admitted. Inspect its exact request; do not replay it.")
}
fn same_context(
    entry: &agent::Entry,
    context: &Context,
    registration: u32,
    root: &RegisteredRoot,
) -> bool {
    let Context::OfflinePreflight(c) = context else {
        return false;
    };
    let s = entry.scope();
    c.operation == wire::Operation::LocalProjectChecks
        && c.platform == wire::Platform::Android
        && c.project_id == s.runtime_id
        && c.draft_revision == s.draft_revision
        && c.baseline_generation == s.baseline_generation
        && c.saved_config.bytes == s.config.bytes
        && c.saved_config.sha256 == s.config.sha256
        && root.path == s.root
        && registration == s.registration
        && root
            .identity
            .posix()
            .is_ok_and(|id| id.service_identity() == (s.device, s.inode))
}
pub(super) fn prepare(
    entry: Option<Arc<agent::Entry>>,
    context: &Context,
    registration: u32,
    root: &RegisteredRoot,
    id: &str,
    generation: &str,
    revision: u32,
) -> Result<Option<Arc<agent::NativeLink>>, BridgeError> {
    let Some(entry) = entry else { return Ok(None) };
    if !same_context(&entry, context, registration, root) || !entry.admission_live() {
        return Err(failure());
    }
    entry
        .bind(
            service::Id::parse(id).map_err(|_| failure())?,
            service::Id::parse(generation).map_err(|_| failure())?,
            revision,
        )
        .map(Some)
        .map_err(|_| failure())
}
pub(super) fn start_matches(prepared: &Prepared, entry: Option<&Arc<agent::Entry>>) -> bool {
    match (&prepared.agent_local_check, entry) {
        (None, None) => true,
        (Some(link), Some(entry)) => {
            link.start_matches(Some(entry))
                && link.matches(
                    &prepared.projection.operation_id,
                    &prepared.projection.owner_generation,
                )
                && same_context(
                    entry,
                    &prepared.projection.context,
                    prepared.registration,
                    &prepared.project,
                )
        }
        _ => false,
    }
}
fn copy_enum<T: serde::de::DeserializeOwned, V: serde::Serialize>(
    value: &V,
) -> Result<T, BridgeError> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| failure())?)
        .map_err(|_| failure())
}
fn projection(
    p: &RunProjection,
    revision: u32,
    retired: bool,
) -> Result<agent::Operation, BridgeError> {
    let Context::OfflinePreflight(context) = &p.context else {
        return Err(failure());
    };
    if context.operation != wire::Operation::LocalProjectChecks {
        return Err(failure());
    }
    let unknown = p.phase == Phase::Unknown;
    let (state, settlement, outcome, result) = if unknown {
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
        let outcome: agent::Outcome = copy_enum(&p.outcome.ok_or_else(failure)?.offline())?;
        let state = match outcome {
            agent::Outcome::Complete => service::OperationState::Succeeded,
            agent::Outcome::Cancelled => service::OperationState::Cancelled,
            agent::Outcome::Failed | agent::Outcome::Refused | agent::Outcome::TimedOut => {
                service::OperationState::Failed
            }
            agent::Outcome::Unknown => return Err(failure()),
        };
        let result = if outcome == agent::Outcome::Complete {
            let Some(Terminal::OfflinePreflight(terminal)) = &p.result else {
                return Err(failure());
            };
            let report = terminal.result.as_ref().ok_or_else(failure)?;
            // Only the ORIGINAL already-validated result, after native retire.
            // Closed typed decoding preserves codes; no arbitrary diagnostics.
            let bytes = crate::edit_protocol::bounded(report, agent::REPORT_LIMIT)?;
            Some(serde_json::from_slice::<agent::Report>(&bytes).map_err(|_| failure())?)
        } else {
            None
        };
        (state, service::Settlement::Settled, Some(outcome), result)
    } else {
        (
            match p.phase {
                Phase::AwaitingConsent => service::OperationState::Prepared,
                Phase::Stopping => service::OperationState::CancellationRequested,
                Phase::Starting | Phase::Running => service::OperationState::Running,
                _ => return Err(failure()),
            },
            service::Settlement::Pending,
            None,
            None,
        )
    };
    let operation = agent::Operation {
        operation_id: service::Id::parse(&p.operation_id).map_err(|_| failure())?,
        owner_generation: service::Id::parse(&p.owner_generation).map_err(|_| failure())?,
        status_revision: revision,
        state,
        settlement,
        outcome,
        reason: if unknown {
            agent::Reason::CleanupUnknown
        } else {
            copy_enum(&p.reason.offline()?)?
        },
        result,
    };
    if !operation.valid() {
        return Err(failure());
    }
    Ok(operation)
}
fn publish(link: &agent::NativeLink, p: &RunProjection, revision: u32, retired: bool) {
    if projection(p, revision, retired)
        .and_then(|p| link.publish(p).map_err(|_| failure()))
        .is_err()
    {
        link.entry().unconfirmed();
    }
}
/// Called by the SAME registry bump. Never locks Doc, Host or Service/store.
pub(super) fn changed(r: &Registry) {
    if let Some(active) = &r.active {
        if let Some(link) = &active.owner.agent_local_check {
            publish(link, &active.projection, r.revision, false);
        }
    } else if let Some(prepared) = &r.prepared {
        if let Some(link) = &prepared.agent_local_check {
            publish(link, &prepared.projection, r.revision, false);
        }
    }
}
/// Prepared cancellation/refusal is genuine no-start retirement, not worker
/// finality. The caller has consumed that exact original Prepared under r.
pub(super) fn retired_prepared(p: &Prepared, reason: Reason, revision: u32) {
    if let Some(link) = &p.agent_local_check {
        publish(link, &retire(p.projection.clone(), reason), revision, true);
    }
}
/// ONLY original reconcile calls this after its positive original watchdog
/// join, material retirement and active->last transition. Helper terminal,
/// observe_final return and public Status do not call this seam.
pub(super) fn retired(active: &Active, revision: u32) {
    if let Some(link) = &active.owner.agent_local_check {
        publish(link, &active.projection, revision, true);
    }
}
impl SavedCommandOwner {
    pub(crate) fn prepare_agent_local_check(
        &self,
        entry: Arc<agent::Entry>,
        registration: u32,
        root: RegisteredRoot,
        gate: wire::Availability,
    ) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
        let s = entry.scope();
        let context = Context::OfflinePreflight(wire::Context {
            project_id: s.runtime_id.clone(),
            draft_revision: s.draft_revision,
            baseline_generation: s.baseline_generation,
            saved_config: wire::Content {
                bytes: s.config.bytes,
                sha256: s.config.sha256.clone(),
            },
            platform: wire::Platform::Android,
            operation: wire::Operation::LocalProjectChecks,
        });
        self.prepare_bound_agent(
            context,
            registration,
            root,
            Availability::from_offline(gate),
            None,
            None,
            Some(entry),
        )?
        .offline()
    }
    pub(crate) fn start_agent_local_check(
        &self,
        entry: &Arc<agent::Entry>,
        at: Instant,
        registered: Option<(u32, RegisteredRoot)>,
        gate: wire::Availability,
    ) -> Result<crate::offline_preflight_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
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
        let a = self.start_bound_agent(
            input,
            at,
            registered,
            Availability::from_offline(gate),
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(crate::offline_preflight_owner::Admitted::new(
            a.status.offline()?,
            a.release,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> (Arc<()>, agent::Inbox, agent::Claim, Arc<agent::NativeLink>) {
        let doc = Arc::new(());
        let (changes, _) = watch::channel(0);
        let id = |c: char| service::Id::parse(&c.to_string().repeat(32)).unwrap();
        let scope = Arc::new(agent::NativeScope {
            project_id: id('c'),
            runtime_id: "project-1".into(),
            root: std::path::PathBuf::from("/unopened-preflight-project"),
            device: 1,
            inode: 2,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(&doc),
            observation_revision: 2,
            config: agent::Config {
                bytes: 123,
                sha256: "f".repeat(64),
            },
            draft_revision: 4,
            baseline_generation: 3,
            changes,
        });
        let inbox = agent::Inbox::new(id('d'));
        inbox.allow(scope.clone()).unwrap();
        inbox
            .submit(
                agent::Submit {
                    service_instance: id('d'),
                    project_id: id('c'),
                    request_id: id('e'),
                    expected_observation_revision: 2,
                },
                &agent::SavedPoint {
                    project_id: id('c'),
                    runtime_id: scope.runtime_id.clone(),
                    root: scope.root.clone(),
                    device: 1,
                    inode: 2,
                    revision: 2,
                    fresh: true,
                    config: Some(scope.config.clone()),
                },
            )
            .unwrap();
        let claim = inbox.claim().unwrap().unwrap();
        let link = claim.entry().bind(id('a'), id('b'), 1).unwrap();
        (doc, inbox, claim, link)
    }
    #[test]
    fn helper_complete_is_pending_until_original_retirement() {
        let mut p = RunProjection {
            agent_local_check: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: Context::OfflinePreflight(wire::Context {
                project_id: "project-1".into(),
                draft_revision: 1,
                baseline_generation: 1,
                saved_config: wire::Content {
                    bytes: 10,
                    sha256: "a".repeat(64),
                },
                platform: wire::Platform::Android,
                operation: wire::Operation::LocalProjectChecks,
            }),
            phase: Phase::Running,
            intent_usable: false,
            outcome: Some(Outcome::Complete),
            reason: Reason::None,
            result: None,
            stage: None,
        };
        let pending = projection(&p, 1, false).unwrap();
        assert_eq!(pending.settlement, service::Settlement::Pending);
        assert_eq!(pending.outcome, None);
        assert!(projection(&p, 1, true).is_err());
        p.phase = Phase::Terminal;
        assert!(projection(&p, 2, true).is_err());
        p.phase = Phase::Unknown;
        assert_eq!(
            projection(&p, 3, false).unwrap().settlement,
            service::Settlement::Unknown
        );
    }
    #[test]
    fn release_scope_and_terminal_shaped_pending_do_not_cross_admission() {
        let mut p = RunProjection {
            agent_local_check: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: Context::OfflinePreflight(wire::Context {
                project_id: "project-1".into(),
                draft_revision: 1,
                baseline_generation: 1,
                saved_config: wire::Content {
                    bytes: 10,
                    sha256: "a".repeat(64),
                },
                platform: wire::Platform::Android,
                operation: wire::Operation::OfflinePreflight,
            }),
            phase: Phase::Terminal,
            intent_usable: false,
            outcome: Some(Outcome::Cancelled),
            reason: Reason::Cancelled,
            result: None,
            stage: None,
        };
        assert!(projection(&p, 1, true).is_err());
        if let Context::OfflinePreflight(c) = &mut p.context {
            c.operation = wire::Operation::LocalProjectChecks;
        }
        assert!(projection(&p, 1, false).is_err());
        assert_eq!(
            projection(&p, 1, true).unwrap().settlement,
            service::Settlement::Settled
        );
    }
    #[test]
    fn actual_common_start_refuses_gui_adoption_before_take_and_retains_no_start_result() {
        let (_doc, _inbox, claim, link) = request();
        let s = link.entry().scope();
        let owner = SavedCommandOwner::offline_preflight(RuntimeConfig::packaged(
            std::path::PathBuf::from("/unopened-local-check-runtime"),
        ));
        let root = RegisteredRoot {
            path: s.root.clone(),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let context = Context::OfflinePreflight(wire::Context {
            project_id: s.runtime_id.clone(),
            draft_revision: s.draft_revision,
            baseline_generation: s.baseline_generation,
            saved_config: wire::Content {
                bytes: s.config.bytes,
                sha256: s.config.sha256.clone(),
            },
            operation: wire::Operation::LocalProjectChecks,
            platform: wire::Platform::Android,
        });
        let prepared = Prepared {
            agent_local_check: Some(link.clone()),
            upload_key_preparation: None,
            upload_key: None,
            apple: None,
            tools: None,
            local_history: None,
            projection: RunProjection {
                agent_local_check: Some(link.origin()),
                operation_id: "a".repeat(32),
                owner_generation: "b".repeat(32),
                context,
                phase: Phase::AwaitingConsent,
                intent_usable: true,
                outcome: None,
                reason: Reason::None,
                result: None,
                stage: None,
            },
            expires: Instant::now() + INTENT,
            registration: 1,
            project: root.clone(),
            recovery_stamp: None,
            material: None,
            recovery: None,
            android_selection: None,
            artifact_selection: None,
            artifact_tools: None,
        };
        {
            let mut r = owner.inner.lock();
            r.revision = 1;
            r.prepared = Some(prepared);
        }
        let gui=wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":wire::LOCAL_CONSENT})).unwrap();
        // Even matching public IDs and the normal local consent cannot claim
        // this original. The forced-unqualified gate rules out native startup.
        assert!(owner
            .start_offline(
                gui,
                Instant::now(),
                Some((1, root.clone())),
                wire::Availability::RuntimeUnqualified
            )
            .is_err());
        assert!(owner.inner.lock().prepared.is_some());
        assert!(owner.inner.lock().active.is_none());
        {
            let mut r = owner.inner.lock();
            if let Context::OfflinePreflight(c) =
                &mut r.prepared.as_mut().unwrap().projection.context
            {
                c.draft_revision += 1;
            }
        }
        assert!(owner
            .start_agent_local_check(
                claim.entry(),
                Instant::now(),
                Some((1, root.clone())),
                wire::Availability::RuntimeUnqualified
            )
            .is_err());
        {
            let mut r = owner.inner.lock();
            if let Context::OfflinePreflight(c) =
                &mut r.prepared.as_mut().unwrap().projection.context
            {
                c.draft_revision -= 1;
            }
        }
        owner
            .start_agent_local_check(
                claim.entry(),
                Instant::now(),
                Some((1, root)),
                wire::Availability::RuntimeUnqualified,
            )
            .unwrap()
            .release();
        {
            let r = owner.inner.lock();
            assert!(r.active.is_none() && r.prepared.is_none());
        }
        let result = claim.entry().status().unwrap().operation.unwrap();
        assert_eq!(
            (result.outcome, result.settlement),
            (Some(agent::Outcome::Refused), service::Settlement::Settled)
        );
        claim.returned(true);
    }
    #[test]
    fn same_original_stop_and_expiry_tighten_clocks_without_settling_or_renewing() {
        for expire in [false, true] {
            let (_doc, _inbox, claim, link) = request();
            let (owner, session) =
                super::super::offline_tests::active_with_agent(Some(link.clone()));
            let inner = &owner.original_for_test().inner;
            assert_eq!(inner.endpoint(&session), Some(link.expires()));
            assert_eq!(session.clocks.work, session.clocks.admitted + OFFLINE_WORK);
            let at = if expire {
                link.expires()
            } else {
                claim.entry().cancel();
                assert!(*session.stop.borrow());
                claim.entry().stop_at(Instant::now()).unwrap()
            };
            {
                let mut r = inner.lock();
                inner.advance_locked(&mut r, &session, at);
                assert_eq!(r.active.as_ref().unwrap().first_stop, Some(at));
                assert_eq!(*session.native_cleanup_cutoff.borrow(), at + SETTLEMENT);
                inner.advance_locked(&mut r, &session, at + SETTLEMENT);
                assert!(r.disabled && r.active.as_ref().unwrap().unknown);
                assert_eq!(r.active.as_ref().unwrap().first_stop, Some(at));
            }
            let status = claim.entry().status().unwrap();
            assert_eq!(
                status.operation.unwrap().settlement,
                service::Settlement::Unknown
            );
            assert!(inner.lock().active.is_some()); // No handle was joined by the clock DATA fixture.
            claim.returned(true);
        }
    }
}
