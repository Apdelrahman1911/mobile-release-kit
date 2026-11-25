//! Closed IOS agent facet INSIDE the existing SavedCommandOwner. The
//! original runtime, Prepared/Session, native jobs and final observer are used.
use super::*;
use crate::{agent_ios_archive as agent, service_protocol as service};
#[path = "saved_command_agent_ios_signed_export.rs"]
mod signed_export;

fn failure() -> BridgeError {
    BridgeError::new("agent_ios_archive_unavailable", "This original IOS build request cannot proceed. Inspect its exact request; do not replay it.")
}
pub(super) fn fixed(input: &ios_wire::Prepare) -> bool {
    signed_export::mode(&input.context()).is_some()
}

fn version(v: &ios_wire::SavedVersion) -> agent::Version {
    agent::Version {
        bytes: v.bytes,
        sha256: v.sha256.clone(),
        name: v.name.clone(),
        build: v.build,
    }
}
/// Only the real Document's fixed Allow route constructs this weak comparison.
/// iOS has no Android catalogue selection. Actual Xcode acquisition/currentness
/// stays in the existing IOSArchiveOwner Start; this is not a tool capability.
pub(crate) struct Approval {
    owner: std::sync::Weak<Inner>,
    document: std::sync::Weak<()>,
    input: ios_wire::Prepare,
    review: agent::Review,
}
impl Approval {
    pub(crate) fn input(&self) -> &ios_wire::Prepare {
        &self.input
    }
    pub(crate) fn review(&self) -> &agent::Review {
        &self.review
    }
    pub(crate) fn signing_backing_bytes(&self) -> Option<usize> {
        signed_export::approval_backing(&self.input, &self.review)
    }
    #[cfg(test)]
    pub(crate) fn signing_backing_data(input: &ios_wire::Prepare) -> Option<usize> {
        signed_export::approval_backing(input, &signed_export::review(&input.context()).ok()?)
    }
    fn current(&self, inner: &Arc<Inner>, _r: &Registry) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && self.document.strong_count() != 0
            && inner.ios_installed_selected()
    }
}
pub(super) struct Preparation {
    pub(super) entry: Arc<agent::Entry>,
    pub(super) approval: Arc<Approval>,
}
fn same_context(
    entry: &agent::Entry,
    c: &Context,
    registration: u32,
    root: &RegisteredRoot,
) -> bool {
    let Context::IOSArchive(c) = c else {
        return false;
    };
    let s = entry.scope();
    let Some(review) = s.review.ios() else {
        return false;
    };
    signed_export::review(c).is_ok_and(|current| &current == review)
        && c.project_id == s.runtime_id
        && s.saved_inputs() == c.draft_revision.zip(c.baseline_generation) && s.saved_inputs().is_some()
        && c.saved_config.as_ref().is_some_and(|v| {
            v.bytes == review.saved_config.bytes && v.sha256 == review.saved_config.sha256
        })
        && c.saved_version
            .as_ref()
            .is_some_and(|v| version(v) == review.saved_version)
        && root.path == s.root
        && registration == s.registration
        && root
            .identity
            .posix()
            .is_ok_and(|i| i.service_identity() == (s.device, s.inode))
}
pub(super) fn prepare(
    input: Option<Preparation>,
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
    let Some(input) = input else { return Ok(None) };
    if !input.approval.current(inner, r)
        || !std::sync::Weak::ptr_eq(&input.approval.document, &input.entry.scope().document)
        || &Context::IOSArchive(input.approval.input.context()) != context
        || Some(&input.approval.review) != input.entry.scope().review.ios()
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
        (None, None) => true,
        (Some(link), Some(entry)) => {
            link.start_matches(agent::FAMILY, Some(entry))
                && link.matches(&p.projection.operation_id, &p.projection.owner_generation)
                && same_context(entry, &p.projection.context, p.registration, &p.project)
        }
        _ => false,
    }
}
pub(super) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    match &p.agent_build {
        Some(link) => link.consume_start(agent::FAMILY).map_err(|_| failure()),
        None => Ok(()),
    }
}
fn copy<T: serde::de::DeserializeOwned, V: serde::Serialize>(value: &V) -> Result<T, BridgeError> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| failure())?)
        .map_err(|_| failure())
}
fn disposition(v: &ios_wire::Disposition) -> Result<agent::Disposition, BridgeError> {
    Ok(agent::Disposition {
        snapshot: copy(&v.snapshot)?,
        work: copy(&v.work)?,
        output: copy(&v.output)?,
    })
}

fn projection(
    p: &RunProjection,
    revision: u32,
    retired: bool,
) -> Result<agent::Operation, BridgeError> {
    let Context::IOSArchive(c) = &p.context else {
        return Err(failure());
    };
    if signed_export::mode(c).is_none() {
        return Err(failure());
    }
    let unknown = p.phase == Phase::Unknown;
    let (state, settlement, outcome, disposition, result) = if unknown {
        (
            service::OperationState::Unknown,
            service::Settlement::Unknown,
            Some(agent::Outcome::Unknown),
            None,
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
        let (disposition, result) = match &p.result {
            Some(Terminal::IOSArchive(t)) => (
                t.disposition.as_ref().map(disposition).transpose()?,
                if outcome == agent::Outcome::Complete {
                    Some(if c.candidate() {
                        t.result.as_ref().ok_or_else(failure)?.agent_candidate_report(c, &p.operation_id)?
                    } else { signed_export::report(c,t.result.as_ref().ok_or_else(failure)?)? })
                } else {
                    None
                },
            ),
            None if outcome != agent::Outcome::Complete => (None, None),
            _ => return Err(failure()),
        };
        (
            state,
            service::Settlement::Settled,
            Some(outcome),
            disposition,
            result,
        )
    } else {
        (
            match p.phase {
                Phase::AwaitingConsent => service::OperationState::Prepared,
                Phase::Starting | Phase::Running => service::OperationState::Running,
                Phase::Stopping => service::OperationState::CancellationRequested,
                _ => return Err(failure()),
            },
            service::Settlement::Pending,
            None,
            None,
            None,
        )
    };
    let output = agent::Operation {
        operation_id: service::Id::parse(&p.operation_id).map_err(|_| failure())?,
        owner_generation: service::Id::parse(&p.owner_generation).map_err(|_| failure())?,
        status_revision: revision,
        state,
        settlement,
        outcome,
        reason: if unknown {
            agent::Reason::CleanupUnknown
        } else {
            copy(&p.reason.ios()?)?
        },
        stage: if unknown {
            None
        } else {
            match p.stage {
                None => None,
                Some(Stage::IOSArchive(stage)) => Some(copy(&stage)?),
                _ => return Err(failure()),
            }
        },
        disposition,
        result,
    };
    if !output.valid_for(&signed_export::review(c)?) {
        return Err(failure());
    }
    Ok(output)
}
fn publish(link: &agent::NativeLink, p: &RunProjection, revision: u32, retired: bool) {
    if projection(p, revision, retired)
        .and_then(|p| link.publish(p).map_err(|_| failure()))
        .is_err()
    {
        link.entry().unconfirmed();
    }
}
// Only SAME original Registry callbacks. No Doc/Host/Service lock or IO here.
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
// Not a helper FINAL or Status read: called after the original watchdog join,
// material/native retirement and SAME active->last transition.
pub(super) fn retired(a: &Active, revision: u32) {
    if let Some(link) = &a.owner.agent_build {
        publish(link, &a.projection, revision, true);
    }
}
impl SavedCommandOwner {
    pub(crate) fn agent_ios_archive_approval_current(
        &self,
        approval: &Approval,
        document: &Arc<()>,
    ) -> bool {
        self.inner.domain == SavedCommandDomain::IOSArchive
            && approval.document.as_ptr() == Arc::as_ptr(document)
            && approval.current(&self.inner, &self.inner.lock())
    }
    pub(crate) fn approve_agent_ios_archive(
        &self,
        input: ios_wire::Prepare,
        document: &Arc<()>,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        let mut input = ios_wire::prepare(&serde_json::to_value(input).map_err(|_| failure())?)?;
        signed_export::compact_policy(&mut input);
        if !fixed(&input) {
            return Err(failure());
        }
        let r = self.inner.lock();
        if !self.inner.ios_installed_selected()
            || !self.inner.ios_mode_qualified(&Context::IOSArchive(input.context()), None)
            || self.inner.availability(&r, Availability::Available) != Availability::Available
        {
            return Err(failure());
        }
        let review = signed_export::review(&input.context())?;
        if !review.valid() {
            return Err(failure());
        }
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            document: Arc::downgrade(document),
            input,
            review,
        }))
    }
    pub(crate) fn prepare_agent_ios_archive(
        &self,
        entry: Arc<agent::Entry>,
        approval: Arc<Approval>,
        registration: u32,
        root: RegisteredRoot,
        gate: ios_wire::Availability,
        material: Option<Arc<IOSSigningMaterial>>,
    ) -> Result<ios_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.prepare_bound_requests(
            Context::IOSArchive(approval.input.context()),
            registration,
            root,
            Availability::from_ios(gate),
            material.map(PrivateSigningMaterial::IOS),
            None,
            None,
            Some(agent_build::Preparation::Ios(Preparation {
                entry,
                approval,
            })),
        )?
        .ios()
    }
    pub(crate) fn agent_ios_archive_prepared_material(&self, entry: &Arc<agent::Entry>) -> Result<Option<Arc<IOSSigningMaterial>>, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        let r = self.inner.lock();
        let p = r.prepared.as_ref().filter(|p| start_matches(p, Some(entry))).ok_or_else(failure)?;
        match &p.material {
            None => Ok(None),
            Some(PrivateSigningMaterial::IOS(original)) => Ok(Some(original.clone())),
            _ => Err(failure()),
        }
    }
    pub(crate) fn start_agent_ios_archive(
        &self,
        entry: &Arc<agent::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: ios_wire::Availability,
        material: Option<Arc<IOSSigningMaterial>>,
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
        let at = entry.start_at().ok_or_else(failure)?;
        let a = self.start_bound_requests(
            input,
            at,
            registered,
            Availability::from_ios(gate),
            material.map(PrivateSigningMaterial::IOS),
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
}

#[cfg(test)]
mod tests {
    // Actual original-memory gates and protocol DATA; runtime forced unqualified.
    // No file, Xcode process, native grant or joined execution is fabricated.
    use super::*;
    fn input() -> ios_wire::Prepare {
        ios_wire::prepare(&serde_json::json!({"projectId":"project-1","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":123,"sha256":"a".repeat(64)},"savedVersion":{"source":"version.properties","bytes":32,"sha256":"b".repeat(64),"name":"1.2.3","build":7}})).unwrap()
    }
    #[test]
    fn fixed_archive_and_export_cannot_borrow_candidate_recovery_or_partial_inputs() {
        let original = input();
        assert!(fixed(&original));
        for action in [
            ios_wire::CreateAction::Create,
            ios_wire::CreateAction::CheckSigning,
        ] {
            let mut v = original.clone();
            v.action = Some(action);
            assert!(!fixed(&v));
        }
        let mut signed = original.clone();
        signed.signing = Some(ios_wire::SigningPolicy {
            team_id: "ABCDE12345".into(),
            distribution_certificate_sha256: "f".repeat(64),
            assignments: vec![],
        });
        // The ordinary native decoder still rejects malformed private policy.
        assert!(ios_wire::prepare(&serde_json::to_value(&signed).unwrap()).is_err());
        signed.signing = ios_wire::tests::signed_context().signing;
        assert!(fixed(&signed));
        let mut v = original.clone();
        v.saved_version = None;
        assert!(!fixed(&v));
        v = original;
        v.recovery = Some(ios_wire::RecoveryIntent {
            action: ios_wire::RecoveryAction::Inspect,
            session: None,
        });
        assert!(!fixed(&v));
        assert!(!fixed(
            &ios_wire::prepare(
                &serde_json::json!({"projectId":"p","recovery":{"action":"inspect"}})
            )
            .unwrap()
        ));
    }
    #[test]
    fn terminal_data_cannot_replace_original_ios_retirement() {
        let mut p = RunProjection {
            agent_local_check: None,
            agent_build: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: Context::IOSArchive(input().context()),
            phase: Phase::Running,
            intent_usable: false,
            outcome: Some(Outcome::Complete),
            reason: Reason::None,
            result: None,
            stage: None,
        };
        assert_eq!(
            projection(&p, 1, false).unwrap().settlement,
            service::Settlement::Pending
        );
        assert!(projection(&p, 1, true).is_err());
        p.phase = Phase::Terminal;
        p.outcome = Some(Outcome::Cancelled);
        p.reason = Reason::Cancelled;
        assert!(projection(&p, 2, false).is_err());
        assert_eq!(
            projection(&p, 2, true).unwrap().settlement,
            service::Settlement::Settled
        );
        p.phase = Phase::Unknown;
        p.reason = Reason::CleanupUnknown;
        assert_eq!(
            projection(&p, 3, false).unwrap().settlement,
            service::Settlement::Unknown
        );
    }
    #[test]
    fn actual_common_start_checks_same_agent_and_context_before_original_take() {
        let id = |c: char| service::Id::parse(&c.to_string().repeat(32)).unwrap();
        let document = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let input = input();
        let scope = Arc::new(agent::NativeScope {
            project_id: id('c'),
            runtime_id: input.project_id.clone(),
            root: "/inert/never-opened".into(),
            device: 1,
            inode: 2,
            registration: 1,
            input_revision: 0,
            document: Arc::downgrade(&document),
            observation_revision: 2,
            read: None,
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: input.draft_revision.unwrap(), baseline_generation: input.baseline_generation.unwrap() },
            changes,
            review: agent::Review {
                mode: agent::Mode::SavedIosUnsignedArchive,
                signing: None,
                saved_config: agent::Config {
                    bytes: input.saved_config.as_ref().unwrap().bytes,
                    sha256: input.saved_config.as_ref().unwrap().sha256.clone(),
                },
                saved_version: version(input.saved_version.as_ref().unwrap()),
            }
            .into(),
        });
        let inbox = agent::Inbox::new(id('e'));
        inbox.allow(scope.clone()).unwrap();
        let request = agent::Prepare {
            service_instance: id('e'),
            project_id: id('c'),
            request_id: id('f'),
            expected_observation_revision: 2,
        };
        inbox
            .prepare(
                agent::FAMILY,
                request.clone(),
                &crate::agent_local_checks::SavedPoint {
                    project_id: id('c'),
                    runtime_id: scope.runtime_id.clone(),
                    root: scope.root.clone(),
                    device: 1,
                    inode: 2,
                    revision: 2,
                    fresh: true,
                    config: Some(scope.review.ios().unwrap().saved_config.clone()),
                },
            )
            .unwrap();
        let preparing = inbox.claim(agent::FAMILY).unwrap().unwrap();
        let expires = Instant::now() + INTENT;
        let link = preparing
            .entry()
            .bind(agent::FAMILY, id('a'), id('b'), 1, expires)
            .unwrap();
        preparing.returned(true);
        let (_, prepared_data) = link.entry().claim_history().unwrap().unwrap();
        // Inert publication bookkeeping only: no native grant/IO was produced.
        link.entry().history_returned(prepared_data.status_revision(), Ok(())).unwrap();
        let owner =
            SavedCommandOwner::ios_archive(RuntimeConfig::packaged("/unopened-ios-runtime".into()));
        let root = RegisteredRoot {
            path: scope.root.clone(),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let prepared = Prepared { agent_history_preparation:None, agent_history:None, agent_store_preparation:None, agent_store:None, store_witness:None,
            agent_build: Some(link.clone()),
            agent_local_check: None,
            upload_key_preparation: None,
            upload_key: None,
            apple: None,
            tools: None,
            local_history: None,
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
            expires,
            registration: 1,
            project: root.clone(),
            recovery_stamp: None,
            material: None,
            recovery: None,
            android_selection: None,
            artifact_selection: None,
            artifact_tools: None,
        };
        assert!(!agent_build::start_matches(&prepared, None));
        {
            let mut r = owner.inner.lock();
            r.revision = 1;
            r.prepared = Some(prepared);
        }
        let gui = ios_wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":ios_wire::CONSENT})).unwrap();
        // Force an unqualified runtime: no native allocation/GO is possible.
        // Even matching public IDs and normal GUI consent cannot take it.
        assert!(owner
            .start_ios(
                gui,
                Instant::now(),
                Some((1, root.clone())),
                ios_wire::Availability::RuntimeUnqualified
            )
            .is_err());
        assert!(owner.inner.lock().prepared.is_some());
        assert!(owner.inner.lock().active.is_none());
        inbox
            .start(
                agent::FAMILY,
                &agent::Start {
                    origin: request.query(),
                    operation_id: id('a'),
                    owner_generation: id('b'),
                },
            )
            .unwrap();
        let starting = inbox.claim(agent::FAMILY).unwrap().unwrap();
        {
            let mut r = owner.inner.lock();
            let Context::IOSArchive(c) = &mut r.prepared.as_mut().unwrap().projection.context
            else {
                panic!("test context")
            };
            c.draft_revision = c.draft_revision.map(|v| v + 1);
        }
        assert!(owner
            .start_agent_ios_archive(
                starting.entry(),
                Some((1, root.clone())),
                ios_wire::Availability::RuntimeUnqualified,
                None,
            )
            .is_err());
        assert!(owner.inner.lock().prepared.is_some());
        assert_eq!(
            starting.entry().status().unwrap().start_state,
            agent::StartState::Admitting
        );
        {
            let mut r = owner.inner.lock();
            let Context::IOSArchive(c) = &mut r.prepared.as_mut().unwrap().projection.context
            else {
                panic!("test context")
            };
            c.draft_revision = c.draft_revision.map(|v| v - 1);
        }
        owner
            .start_agent_ios_archive(
                starting.entry(),
                Some((1, root)),
                ios_wire::Availability::RuntimeUnqualified,
                None,
            )
            .unwrap()
            .release();
        {
            let r = owner.inner.lock();
            assert!(r.prepared.is_none() && r.active.is_none());
        }
        let entry = starting.entry().clone();
        assert!(entry.claim_history().unwrap().is_none());
        assert!(entry.status().unwrap().operation.as_ref().is_some_and(|o|
            o.settlement() == service::Settlement::Pending));
        starting.returned(true);
        let (_, refused_data) = entry.claim_history().unwrap().unwrap();
        entry.history_returned(refused_data.status_revision(), Ok(())).unwrap();
        let result = entry.status().unwrap();
        assert_eq!(result.start_state, agent::StartState::Consumed);
        let operation = result.operation.unwrap();
        let crate::agent_build_requests::Operation::Ios(result) = operation else {
            panic!("wrong family")
        };
        assert_eq!(
            (result.outcome, result.settlement),
            (Some(agent::Outcome::Refused), service::Settlement::Settled)
        );
        assert!(inbox.claim(agent::FAMILY).unwrap().is_none());
    }

    #[test]
    fn native_projection_keeps_closed_family_and_unsigned_mode() {
        let q = agent::Query {
            service_instance: service::Id::parse(&"a".repeat(32)).unwrap(),
            project_id: service::Id::parse(&"b".repeat(32)).unwrap(),
            request_id: service::Id::parse(&"c".repeat(32)).unwrap(),
        };
        let mut p = RunProjection {
            agent_local_check: None,
            agent_build: Some(crate::agent_build_requests::Origin::Ios(q.clone())),
            operation_id: "d".repeat(32),
            owner_generation: "e".repeat(32),
            context: Context::IOSArchive(input().context()),
            phase: Phase::AwaitingConsent,
            intent_usable: true,
            outcome: None,
            reason: Reason::None,
            result: None,
            stage: None,
        };
        let value = serde_json::to_value(p.clone().ios().unwrap()).unwrap();
        assert_eq!(value["agentIosArchive"], serde_json::to_value(&q).unwrap());
        assert!(serde_json::from_value::<ios_wire::Projection>(value).is_ok());
        p.agent_build = Some(crate::agent_build_requests::Origin::Android(q));
        assert!(p.ios().is_err());
    }
    #[test]
    fn same_original_unsigned_result_projects_only_real_counts_without_digest_or_paths() {
        let context = ios_wire::tests::context();
        let terminal =
            ios_wire::terminal(&ios_wire::tests::complete(), &context, &"a".repeat(32)).unwrap();
        let result = signed_export::report(&context,terminal.result.as_ref().unwrap()).unwrap();
        assert!(result.valid());
        assert_eq!((result.entries, result.bytes), (10, 1000));
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        for field in [
            "sha256", "archive", "bundleId", "teamId", "ipa", "path", "signing",
        ] {
            assert!(value.get(field).is_none());
        }
        assert!(value["usedVersion"].get("source").is_none());
        assert!(!serde_json::to_string(&value)
            .unwrap()
            .contains("version.properties"));
    }
    #[test]
    fn candidate_terminal_projection_still_requires_original_retirement() {
        let context=ios_wire::tests::candidate_context();let raw=ios_wire::tests::candidate_complete();
        let terminal=ios_wire::terminal(&raw, &context, ios_wire::tests::CANDIDATE_ID).unwrap();
        let mut p=RunProjection {agent_local_check:None,agent_build:None,operation_id:ios_wire::tests::CANDIDATE_ID.into(),owner_generation:"b".repeat(32),
            context:Context::IOSArchive(context),phase:Phase::Stopping,intent_usable:false,outcome:Some(Outcome::Complete),reason:Reason::None,
            result:Some(Terminal::IOSArchive(terminal)),stage:Some(Stage::IOSArchive(ios_wire::Stage::DisposingWork))};
        let pending=projection(&p,1,false).unwrap();assert!(pending.result.is_none());assert_eq!(pending.settlement,service::Settlement::Pending);
        assert!(projection(&p,1,true).is_err());p.phase=Phase::Terminal;assert!(projection(&p,2,false).is_err());
        let known=projection(&p,2,true).unwrap();assert!(known.result.as_ref().unwrap().candidate.is_some());assert_eq!(known.settlement,service::Settlement::Settled);
        p.phase=Phase::Unknown;p.reason=Reason::CleanupUnknown;let unknown=projection(&p,3,false).unwrap();assert!(unknown.result.is_none());assert_eq!(unknown.settlement,service::Settlement::Unknown);
    }

}
