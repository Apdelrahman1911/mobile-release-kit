//! Closed Android agent facet INSIDE the existing SavedCommandOwner. The
//! original runtime, Prepared/Session, native jobs and final observer are used.
use super::*;
use crate::{agent_android_build as agent, service_protocol as service};
use serde_json::Value;
#[path = "saved_command_agent_android_signed.rs"]
mod signed;

fn failure() -> BridgeError {
    BridgeError::new("agent_android_build_unavailable", "This original Android build request cannot proceed. Inspect its exact request; do not replay it.")
}
pub(super) fn fixed(input: &android_wire::Prepare) -> bool {
    input.signing.is_none()
        && input.operation.is_none()
        && input.action.is_none()
        && input.artifact_validation.mode == android_wire::ValidationMode::StructureAndVersion
        && input
            .artifact_validation
            .upload_certificate_sha256
            .is_none()
}
fn version(v: &android_wire::SavedVersion) -> agent::Version {
    agent::Version {
        bytes: v.bytes,
        sha256: v.sha256.clone(),
        name: v.name.clone(),
        build: v.build,
    }
}
/// Weak comparison of the already selected native catalog original. This is
/// NOT a new tool loan and retains no second catalog/native resource graph.
pub(crate) struct Approval {
    owner: std::sync::Weak<Inner>,
    selected: std::sync::Weak<android_catalog::Selection>,
    input: android_wire::Prepare,
    review: agent::Review,
}
impl Approval {
    pub(crate) fn input(&self) -> &android_wire::Prepare {
        &self.input
    }
    pub(crate) fn review(&self) -> &agent::Review {
        &self.review
    }
    fn current(&self, inner: &Arc<Inner>, r: &Registry) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(inner)
            && r.android_catalog.selection().is_some_and(|selected| {
                self.selected.as_ptr() == Arc::as_ptr(selected) && selected.matches_owner(inner)
            })
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
    let Context::AndroidBuild(c) = c else {
        return false;
    };
    let s = entry.scope();
    let Some(review) = s.review.android() else { return false };
    (if matches!(review.mode, agent::Mode::SavedAndroidLocalUploadKeySign | agent::Mode::SavedAndroidCandidateInputs) { signed::same(c, review) }
        else { c.operation == android_wire::Operation::AndroidBuildInspect && c.signing.is_none() && c.action.is_none()
            && c.artifact_validation.mode == android_wire::ValidationMode::StructureAndVersion
            && c.artifact_validation.upload_certificate_sha256.is_none() })
        && c.project_id == s.runtime_id
        && s.saved_inputs() == Some((c.draft_revision, c.baseline_generation))
        && c.saved_config.bytes == review.saved_config.bytes
        && c.saved_config.sha256 == review.saved_config.sha256
        && version(&c.saved_version) == review.saved_version
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
        || &Context::AndroidBuild(input.approval.input.context()) != context
        || Some(&input.approval.review) != input.entry.scope().review.android()
        || !same_context(&input.entry, context, registration, root)
        || !input.entry.prepare_live()
    {
        return Err(failure());
    }
    input
        .entry
        .bind(agent::FAMILY,
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
fn report(value: &android_wire::ResultValue) -> Result<agent::Report, BridgeError> {
    // The original, strictly validated native terminal is already public DATA.
    // Bound its one serialized copy before the finite projection. No raw text,
    // saved paths, catalog paths, source IDs or artifact filename crosses CLI.
    let bytes = crate::edit_protocol::bounded(value, android_wire::RESPONSE_LIMIT)?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| failure())?;
    if v.get("scope").and_then(Value::as_str) != Some(android_wire::SCOPE)
        || v.get("signing").is_some()
        || v.pointer("/artifactValidation/mode")
            .and_then(Value::as_str)
            != Some("structure-and-version")
        || !v
            .get("artifacts")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 1)
    {
        return Err(failure());
    }
    let projected = serde_json::json!({"scope":v["scope"],"usedConfig":v["usedConfig"],
        "usedVersion":{"bytes":v["usedVersion"]["bytes"],"sha256":v["usedVersion"]["sha256"],"name":v["usedVersion"]["name"],"build":v["usedVersion"]["build"]},
        "findings":v["findings"],"summary":v["summary"],"artifact":{"size":v["artifacts"][0]["size"],"sha256":v["artifacts"][0]["sha256"]}});
    let bytes = crate::edit_protocol::bounded(&projected, agent::REPORT_LIMIT)?;
    let result: agent::Report = serde_json::from_slice(&bytes).map_err(|_| failure())?;
    if !result.valid() {
        return Err(failure());
    }
    Ok(result)
}
fn projection(
    p: &RunProjection,
    revision: u32,
    retired: bool,
) -> Result<agent::Operation, BridgeError> {
    let Context::AndroidBuild(c) = &p.context else {
        return Err(failure());
    };
    if !c.agent_context()
    {
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
        let outcome: agent::Outcome = copy(&p.outcome.ok_or_else(failure)?.android())?;
        let state = match outcome {
            agent::Outcome::Complete => service::OperationState::Succeeded,
            agent::Outcome::Cancelled => service::OperationState::Cancelled,
            agent::Outcome::Refused | agent::Outcome::Failed | agent::Outcome::TimedOut => {
                service::OperationState::Failed
            }
            agent::Outcome::Unknown => return Err(failure()),
        };
        let (disposition, result) = match &p.result {
            Some(Terminal::AndroidBuild(t)) => (
                Some(copy(&t.disposition)?),
                if outcome == agent::Outcome::Complete {
                    let native = t.result.as_ref().ok_or_else(failure)?;
                    Some(if c.candidate() { native.agent_candidate_report(c, &p.operation_id)? }
                        else if c.signed() { native.agent_signed_report(c)? } else { report(native)? })
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
            copy(&p.reason.android()?)?
        },
        stage: if unknown {
            None
        } else {
            match p.stage {
                None => None,
                Some(Stage::AndroidBuild(stage)) => Some(copy(&stage)?),
                _ => return Err(failure()),
            }
        },
        disposition,
        result,
    };
    if !output.valid() {
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
    pub(crate) fn agent_android_build_approval_current(
        &self,
        approval: &Approval,
        document: &Arc<()>,
    ) -> bool {
        self.inner.domain == SavedCommandDomain::AndroidBuild
            && self.inner.android_original_document_matches(Some(document))
            && approval.current(&self.inner, &self.inner.lock())
    }
    pub(crate) fn approve_agent_android_build(
        &self,
        input: android_wire::Prepare,
        selected: &android_wire::MacToolchainSelection,
        document: &Arc<()>,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        let input = android_wire::prepare(&serde_json::to_value(input).map_err(|_| failure())?)?;
        if !(fixed(&input) || signed::fixed(&input)) || !self.inner.android_original_document_matches(Some(document)) {
            return Err(failure());
        }
        let r = self.inner.lock();
        if self.inner.availability(&r, Availability::Available) != Availability::Available
            || !self
                .inner
                .android_installed_selected(Some(document), r.android_catalog.selection())
        {
            return Err(failure());
        }
        let original = r
            .android_catalog
            .selection()
            .filter(|s| s.data() == selected && s.matches_owner(&self.inner))
            .ok_or_else(failure)?;
        let review = agent::Review {
            mode: if input.context().candidate() { agent::Mode::SavedAndroidCandidateInputs }
                else if input.signing.is_some() { agent::Mode::SavedAndroidLocalUploadKeySign } else { agent::Mode::SavedAndroidBuildStructureAndVersion },
            signing: input.signing.as_ref().map(signed::selection).transpose()?,
            upload_certificate_sha256: input.artifact_validation.upload_certificate_sha256.as_deref().and_then(agent::signed::fingerprint),
            saved_config: agent::Config {
                bytes: input.saved_config.bytes,
                sha256: input.saved_config.sha256.clone(),
            },
            saved_version: version(&input.saved_version),
            tools: agent::Tools {
                instance: service::Id::parse(&selected.instance).map_err(|_| failure())?,
                catalog_generation: selected.catalog_generation,
                record_sha256: selected.record_sha256.clone(),
            },
        };
        if !review.valid() {
            return Err(failure());
        }
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            selected: Arc::downgrade(original),
            input,
            review,
        }))
    }
    pub(crate) fn prepare_agent_android_build(
        &self,
        entry: Arc<agent::Entry>,
        approval: Arc<Approval>,
        registration: u32,
        root: RegisteredRoot,
        gate: android_wire::Availability,
        material: Option<Arc<crate::asset_session::AndroidSigningMaterial>>,
    ) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        if approval.input.signing.is_some() != material.is_some() { return Err(failure()); }
        self.prepare_bound_requests(
            Context::AndroidBuild(approval.input.context()),
            registration,
            root,
            Availability::from_android(gate),
            material.map(PrivateSigningMaterial::Android),
            None,
            None,
            Some(agent_build::Preparation::Android(Preparation { entry, approval })),
        )?
        .android()
    }
    /// SAME retained Prepared material, never a fresh replacement wrapper.
    pub(crate) fn agent_android_build_material(&self, entry: &Arc<agent::Entry>)
        -> Result<Option<Arc<crate::asset_session::AndroidSigningMaterial>>, BridgeError>
    {
        let r = self.inner.lock();
        let p = r.prepared.as_ref().filter(|p| start_matches(p, Some(entry))).ok_or_else(failure)?;
        match (&p.projection.context, &p.material) {
            (Context::AndroidBuild(c), Some(PrivateSigningMaterial::Android(m)))
                if c.agent_context() && c.signed() => Ok(Some(m.clone())),
            (Context::AndroidBuild(c), None) if c.operation == android_wire::Operation::AndroidBuildInspect => Ok(None),
            _ => Err(failure()),
        }
    }
    pub(crate) fn start_agent_android_build(
        &self,
        entry: &Arc<agent::Entry>,
        registered: Option<(u32, RegisteredRoot)>,
        gate: android_wire::Availability,
        material: Option<Arc<crate::asset_session::AndroidSigningMaterial>>,
    ) -> Result<crate::android_build_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        let input = {
            let r = self.inner.lock();
            let p = r
                .prepared
                .as_ref()
                .filter(|p| start_matches(p, Some(entry)))
                .ok_or_else(failure)?;
            if !match (&p.material, &material) {
                (None, None) => true,
                (Some(PrivateSigningMaterial::Android(a)), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            } { return Err(failure()); }
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
            Availability::from_android(gate),
            material.map(PrivateSigningMaterial::Android),
            None,
            None,
            None,
            Some(entry),
        )?;
        Ok(crate::android_build_owner::Admitted::new(
            a.status.android()?,
            a.release,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> android_wire::Prepare {
        android_wire::prepare(&serde_json::json!({"projectId":"project-1","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":123,"sha256":"a".repeat(64)},"savedVersion":{"source":"version.properties","bytes":32,"sha256":"b".repeat(64),"name":"1.2.3","build":7},
            "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})).unwrap()
    }
    #[test]
    fn named_scope_cannot_borrow_signing_candidate_or_signature_inspection() {
        let mut i = input();
        assert!(fixed(&i));
        i.artifact_validation.mode = android_wire::ValidationMode::UploadSignature;
        assert!(!fixed(&i));
        i = input();
        i.operation = Some(android_wire::Operation::AndroidCandidateInputs);
        assert!(!fixed(&i));
        i = input();
        i.action = Some(android_wire::CreateAction::Create);
        assert!(!fixed(&i));
        i = input();
        i.signing = Some(android_wire::SigningSelection {
            mode: android_wire::SigningMode::LocalUploadKey,
            assignments: vec![],
        });
        assert!(!fixed(&i));
    }
    #[test]
    fn terminal_shaped_data_cannot_replace_the_original_retirement_callback() {
        let mut p = RunProjection {
            agent_local_check: None,
            agent_build: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: Context::AndroidBuild(input().context()),
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
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: input.draft_revision, baseline_generation: input.baseline_generation },
            changes,
            review: agent::Review {
                mode: agent::Mode::SavedAndroidBuildStructureAndVersion,
                signing: None, upload_certificate_sha256: None,
                saved_config: agent::Config {
                    bytes: input.saved_config.bytes,
                    sha256: input.saved_config.sha256.clone(),
                },
                saved_version: version(&input.saved_version),
                tools: agent::Tools {
                    instance: id('d'),
                    catalog_generation: 1,
                    record_sha256: "c".repeat(64),
                },
            }.into(),
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
            .prepare(agent::FAMILY,
                request.clone(),
                &crate::agent_local_checks::SavedPoint {
                    project_id: id('c'),
                    runtime_id: scope.runtime_id.clone(),
                    root: scope.root.clone(),
                    device: 1,
                    inode: 2,
                    revision: 2,
                    fresh: true,
                    config: Some(scope.review.android().unwrap().saved_config.clone()),
                },
            )
            .unwrap();
        let preparing = inbox.claim(agent::FAMILY).unwrap().unwrap();
        let expires = Instant::now() + INTENT;
        let link = preparing
            .entry()
            .bind(agent::FAMILY,id('a'), id('b'), 1, expires)
            .unwrap();
        preparing.returned(true);
        let (_, published) = link.entry().claim_history().unwrap().unwrap();
        link.entry().history_returned(published.status_revision(), Ok(())).unwrap();
        let owner = SavedCommandOwner::android_build(
            RuntimeConfig::packaged("/unopened-android-runtime".into()),
            None,
        );
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
                context: Context::AndroidBuild(input.context()),
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
        {
            let mut r = owner.inner.lock();
            r.revision = 1;
            r.prepared = Some(prepared);
        }
        let gui = android_wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":android_wire::CONSENT})).unwrap();
        // Force an unqualified runtime: no native allocation/GO is possible.
        // Even matching public IDs and normal GUI consent cannot take it.
        assert!(owner
            .start_android(
                gui,
                Instant::now(),
                Some((1, root.clone())),
                android_wire::Availability::RuntimeUnqualified,
            )
            .is_err());
        assert!(owner.inner.lock().prepared.is_some());
        assert!(owner.inner.lock().active.is_none());
        inbox
            .start(agent::FAMILY,&agent::Start {
                origin: request.query(),
                operation_id: id('a'),
                owner_generation: id('b'),
            })
            .unwrap();
        let starting = inbox.claim(agent::FAMILY).unwrap().unwrap();
        {
            let mut r = owner.inner.lock();
            let Context::AndroidBuild(c) = &mut r.prepared.as_mut().unwrap().projection.context
            else {
                panic!("test context")
            };
            c.draft_revision += 1;
        }
        assert!(owner
            .start_agent_android_build(
                starting.entry(),
                Some((1, root.clone())),
                android_wire::Availability::RuntimeUnqualified,
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
            let Context::AndroidBuild(c) = &mut r.prepared.as_mut().unwrap().projection.context
            else {
                panic!("test context")
            };
            c.draft_revision -= 1;
        }
        owner
            .start_agent_android_build(
                starting.entry(),
                Some((1, root)),
                android_wire::Availability::RuntimeUnqualified,
                None,
            )
            .unwrap()
            .release();
        {
            let r = owner.inner.lock();
            assert!(r.prepared.is_none() && r.active.is_none());
        }
        let waiting = starting.entry().status().unwrap();
        assert_eq!(waiting.start_state, agent::StartState::Consumed);
        assert_eq!(waiting.operation.unwrap().state(), service::OperationState::Prepared);
        assert!(starting.entry().claim_history().unwrap().is_none());
        starting.returned(true);
        let (_, returned) = link.entry().claim_history().unwrap().unwrap();
        link.entry().history_returned(returned.status_revision(), Ok(())).unwrap();
        let result = link.entry().status().unwrap();
        let operation = result.operation.unwrap();
        let result = operation.android();
        assert_eq!(
            (result.outcome, result.settlement),
            (Some(agent::Outcome::Refused), service::Settlement::Settled)
        );
        assert!(inbox.claim(agent::FAMILY).unwrap().is_none());
    }
    #[test]
    fn original_validated_result_projection_drops_labels_paths_and_preserves_failed_checks() {
        let i = input();
        let counts = serde_json::json!({"PASS":0,"FAIL":1,"MISSING":0,"BLOCKED":0,"INVALID":0,"SKIP":0,"MANUAL":0,"CONFIGURED":0,"NOT_APPLICABLE":0});
        let value = serde_json::json!({"schemaVersion":1,"scope":android_wire::SCOPE,"usedConfig":i.saved_config,"usedVersion":i.saved_version,
            "artifactValidation":i.artifact_validation,"selection":{"module":":app","variant":"release","applicationId":"org.example.app","task":":app:bundleRelease"},
            "toolchainProfile":android_wire::TOOLCHAIN_PROFILE,"command":{"outcome":"exited","exitCode":0},
            "findings":[{"ordinal":0,"check":"aab-structure","status":"FAIL"}],"summary":{"total":1,"shown":1,"omitted":0,"counts":counts},
            "artifacts":[{"logicalName":"android-aab","platform":"android","kind":"aab","fileName":"app-release.aab","size":1024,"sha256":"c".repeat(64),
                "architectures":["arm64-v8a"],"unknownAbi":false,"freshness":"not-established"}],
            "assurances":{"structure":"failed","nativeManifest":"not-checked","applicationVersion":"not-established","signature":"not-inspected","signer":"not-inspected",
                "toolkitSigning":"not-requested","storeOperation":"not-requested","sourceBinding":"not-established","releaseReadiness":"not-assessed"},
            "limitations":["saved-inputs-not-atomic","project-code-effects-possible","not-network-isolated","post-run-bytes-may-be-incremental-reused-or-stale",
                "source-binding-not-established","artifact-signer-not-inspected","toolkit-signing-not-requested","store-operation-not-requested","release-readiness-not-assessed",
                "local-output-observation-not-current-file-authority","core-terminal-requires-original-native-finality"]});
        // Real original protocol validation, not a fabricated native receipt.
        let original = android_wire::ResultValue::Build(android_wire::result(&value).unwrap());
        let result = report(&original).unwrap();
        assert!(result.valid());
        assert_eq!(result.summary.counts[&agent::FindingStatus::Fail], 1);
        assert_eq!(result.artifact.size, 1024);
        let json = serde_json::to_value(&result).unwrap();
        for label in [
            "selection",
            "command",
            "toolchainProfile",
            "toolchainSelection",
            "signing",
            "artifacts",
            "assurances",
        ] {
            assert!(json.get(label).is_none());
        }
        assert!(json["usedVersion"].get("source").is_none());
        let encoded = serde_json::to_string(&result).unwrap();
        for text in [
            "org.example.app",
            "version.properties",
            "app-release.aab",
            ":app:bundleRelease",
        ] {
            assert!(!encoded.contains(text));
        }
    }
    #[test]
    fn candidate_terminal_projection_still_requires_original_retirement() {
        let context=android_wire::tests::candidate_context();let raw=android_wire::tests::candidate_complete();
        let terminal=android_wire::terminal(&raw, &context).unwrap();
        let mut p=RunProjection {agent_local_check:None,agent_build:None,operation_id:android_wire::tests::CANDIDATE_ID.into(),owner_generation:"b".repeat(32),
            context:Context::AndroidBuild(context),phase:Phase::Stopping,intent_usable:false,outcome:Some(Outcome::Complete),reason:Reason::None,
            result:Some(Terminal::AndroidBuild(terminal)),stage:Some(Stage::AndroidBuild(android_wire::Stage::DisposingWork))};
        let pending=projection(&p,1,false).unwrap();assert!(pending.result.is_none());assert_eq!(pending.settlement,service::Settlement::Pending);
        assert!(projection(&p,1,true).is_err());p.phase=Phase::Terminal;assert!(projection(&p,2,false).is_err());
        let known=projection(&p,2,true).unwrap();assert!(known.result.as_ref().unwrap().candidate.is_some());assert_eq!(known.settlement,service::Settlement::Settled);
        p.phase=Phase::Unknown;p.reason=Reason::CleanupUnknown;let unknown=projection(&p,3,false).unwrap();assert!(unknown.result.is_none());assert_eq!(unknown.settlement,service::Settlement::Unknown);
    }

}
