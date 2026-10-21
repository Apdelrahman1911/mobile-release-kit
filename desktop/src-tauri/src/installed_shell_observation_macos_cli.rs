//! One fixed local-check request through the ordinary installed CLI and the
//! genuine Desktop service. No socket client, grant, worker or receipt is made
//! here. The existing relay awaits the existing Document APIs off Record/Doc.
use super::{Case, DocumentBinding, Observation, Step as OuterStep, CONFIG};
use crate::{
    agent_local_checks as agent, error::BridgeError, offline_preflight_protocol as offline,
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};

#[path = "installed_shell_observation_macos_cli_fixture.rs"]
mod fixture;
pub(super) const NAME: &str = "installed-cli-local-check";
pub(super) const SECONDS: u64 = 120;
const WINDOW: &str = "main";
// Fixed observer-only DATA/parse backing, separate from the existing service
// DOCUMENT_BACKING and process owners: two4KiB files, <=16 original FDs,
// one original <=64KiB projection plus fixed <=8KiB/32-finding fixture
// conversions. These smaller observation limits do not alter the service ABI.
pub(super) const BACKING: usize = 256 * 1024;
const FIXTURE_REPORT_LIMIT: usize = 8192;
const FIXTURE_FINDINGS: usize = 32;
pub(super) fn selected(role: Option<&str>, scope: Option<&str>, arm: bool) -> bool {
    arm && role == Some("installed-shell-observation") && scope == Some("tool-setup")
}
pub(super) fn admitted() -> bool {
    selected(
        option_env!("MRK_MACOS_PACKAGE_ROLE"),
        option_env!("MRK_MACOS_NATIVE_SCOPE"),
        cfg!(target_arch = "aarch64"),
    )
}
pub(super) fn application(uid: u32) -> Option<PathBuf> {
    if !admitted() {
        return None;
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    if uid == 0 || user.uid.as_raw() != uid || !user.dir.is_absolute() {
        return None;
    }
    let (s, r, a) = (
        option_env!("GITHUB_SHA")?,
        option_env!("GITHUB_RUN_ID")?,
        option_env!("GITHUB_RUN_ATTEMPT")?,
    );
    let tag = super::digest(format!("{s}/{r}/{a}/{NAME}").as_bytes());
    let home = user.dir.join(format!(".c-{}", &tag[..12]));
    let app = home.join("Library/Application Support/dev.mobile-release-kit.desktop");
    if app.join("service-v1/s").as_os_str().len() >= 104
        || std::env::var_os("HOME").as_deref() != Some(home.as_os_str())
    {
        return None;
    }
    Some(app)
}
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k)))
}
fn canonical(mut v: Value) -> Result<String, ()> {
    // Explicit sorting also when another dependency enables preserve_order.
    // This typed report contains only ASCII enums, hashes and integer DATA.
    v.sort_all_objects();
    let raw = crate::edit_protocol::bounded(&v, FIXTURE_REPORT_LIMIT).map_err(|_| ())?;
    Ok(super::digest(&raw))
}
fn config() -> agent::Config {
    agent::Config {
        bytes: CONFIG.len() as u32,
        sha256: super::digest(CONFIG),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Allow,
    Submitted,
    Terminal,
    Checked,
    Denied,
    Done,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Completed {
    operation: String,
    generation: String,
    digest: String,
}
pub(super) struct Record {
    files: fixture::Files,
    project: Option<crate::service_protocol::Id>,
    revision: Option<u64>,
    origin: Option<agent::Query>,
    completed: Option<Completed>,
    consumed: bool,
    checked: bool,
    revoked: bool,
    reallowed: bool,
    driver_done: bool,
    readback: bool,
    host: Option<usize>,
}
fn completed(
    p: &offline::Projection,
    origin: &agent::Query,
    project: &str,
) -> Result<Completed, ()> {
    if p.agent_local_check.as_ref() != Some(origin)
        || p.phase != offline::Phase::Terminal
        || p.intent_usable
        || p.outcome != Some(offline::Outcome::Complete)
        || p.reason != offline::Reason::None
        || p.context.project_id != project
        || p.context.draft_revision != 0
        || p.context.baseline_generation != 1
        || p.context.operation != offline::Operation::LocalProjectChecks
        || p.context.saved_config.bytes != CONFIG.len() as u32
        || p.context.saved_config.sha256 != super::digest(CONFIG)
    {
        return Err(());
    }
    let raw = crate::edit_protocol::bounded(p.result.as_ref().ok_or(())?, FIXTURE_REPORT_LIMIT)
        .map_err(|_| ())?;
    let report: agent::Report = serde_json::from_slice(&raw).map_err(|_| ())?;
    if !report.valid() || report.used_config != config() || report.findings.len() > FIXTURE_FINDINGS
    {
        return Err(());
    }
    let rows = &report.findings;
    if ![
        (
            agent::Check::AndroidGradleWrapper,
            agent::CoreStatus::Missing,
        ),
        (agent::Check::VersionSource, agent::CoreStatus::Pass),
        (
            agent::Check::WorkspacePrivateOutput,
            agent::CoreStatus::Pass,
        ),
    ]
    .iter()
    .all(|(check, status)| {
        rows.iter()
            .any(|r| r.check == *check && r.status == *status)
    }) || rows
        .iter()
        .any(|r| r.project_check_index.is_some() || r.check == agent::Check::ConfiguredProjectCheck)
    {
        return Err(());
    }
    Ok(Completed {
        operation: p.operation_id.clone(),
        generation: p.owner_generation.clone(),
        digest: canonical(serde_json::to_value(report).map_err(|_| ())?)?,
    })
}
fn host_return(settled: bool, no_failures: bool, joined: Option<usize>) -> bool {
    settled && no_failures && joined == Some(8)
}
impl Record {
    pub(super) fn new(project: &std::path::Path, uid: u32) -> Result<Self, ()> {
        if !admitted() || std::mem::size_of::<Self>() > BACKING {
            return Err(());
        }
        Ok(Self {
            files: fixture::Files::capture(project, uid)?,
            project: None,
            revision: None,
            origin: None,
            completed: None,
            consumed: false,
            checked: false,
            revoked: false,
            reallowed: false,
            driver_done: false,
            readback: false,
            host: None,
        })
    }
    fn same(&self, p: &offline::Projection, project: &str) -> Result<(), ()> {
        let c = completed(p, self.origin.as_ref().ok_or(())?, project)?;
        if self.completed.as_ref() != Some(&c) {
            return Err(());
        }
        Ok(())
    }
    pub(super) fn report(&self) -> Option<Value> {
        let c = self.completed.as_ref()?;
        if !self.consumed
            || !self.checked
            || !self.revoked
            || !self.reallowed
            || !self.driver_done
            || !self.readback
            || !self.files.closed()
            || self.host != Some(8)
        {
            return None;
        }
        Some(
            json!({"schemaVersion":1,"scope":NAME,"origin":self.origin.as_ref()?,
            "operationId":c.operation,"ownerGeneration":c.generation,"reportSha256":c.digest,
            "consumedPermission":true,"sameOriginalAfterLateStop":true,"readRevoked":true,"readReallowedOnly":true,
            "driverSequenceCompared":true,"phaseOriginalsClosed":true,"hostWorkersJoined":8,"hostOriginalsClosed":true,
            "projectFilesUnchanged":true,"liveInterruptionTested":false,"applicationRestartTested":false}),
        )
    }
}
impl Observation {
    /// Called only by the original relay. File/Record guards are never retained
    /// across an await or original Document/Host operation.
    pub(super) async fn cli_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        let result:Result<Option<Step>,BridgeError>=async {
            let bad=BridgeError::invalid;
            if self.case!=Case::Cli||!admitted(){return Err(bad());}
            let project=self.record().and_then(|r|r.project.as_ref().map(|p|p.id.clone())).ok_or_else(bad)?;
            Ok(match step {
                Step::Allow=>{
                    let path=self.record().and_then(|r|r.cli.as_ref()?.files.application().ok()).ok_or_else(bad)?;
                    let checked=document.application_read_status()?;
                    let read=document.allow_application_read(&project,checked.permission_revision,&path).await?;
                    if !read.enabled||read.remaining_ms==0||read.project_ids.len()!=1{return Err(bad());}
                    let checked=document.agent_local_check_access(WINDOW)?;
                    let args=serde_json::from_value(json!({"projectId":project,"draftRevision":0,"baselineGeneration":1,
                        "consentVersion":agent::CONSENT,"expectedPermissionRevision":checked.permission_revision})).map_err(|_|bad())?;
                    let grant=document.allow_agent_local_check(WINDOW,args)?.access;
                    let id=read.project_ids[0].clone();
                    if !grant.enabled||grant.consumed||grant.project_id.as_ref()!=Some(&id)||grant.remaining_ms==0
                        ||grant.observation_revision.is_none_or(|n|n==0){return Err(bad());}
                    let mut r=self.record().ok_or_else(bad)?;let c=r.cli.as_mut().ok_or_else(bad)?;
                    if c.project.is_some()||c.revision.is_some(){return Err(bad());}
                    c.project=Some(id.clone());c.revision=grant.observation_revision;
                    c.files.send(&json!({"phase":"allowed","projectId":id,"revision":c.revision,"config":config()})).map_err(|_|bad())?;
                    Some(Step::Submitted)
                },
                Step::Submitted=>{
                    let mut r=self.record().ok_or_else(bad)?;let c=r.cli.as_mut().ok_or_else(bad)?;
                    if let Some(v)=c.files.poll(0,"submitted").map_err(|_|bad())?{
                        if !keys(&v,&["phase","origin","revision"])||v["revision"].as_u64()!=c.revision||c.origin.is_some(){return Err(bad());}
                        let origin:agent::Query=serde_json::from_value(v["origin"].clone()).map_err(|_|bad())?;
                        if Some(&origin.project_id)!=c.project.as_ref(){return Err(bad());}
                        c.origin=Some(origin);Some(Step::Terminal)
                    }else{None}
                },
                Step::Terminal=>{
                    let status=document.offline_preflight_status()?;
                    let Some(p)=status.operation.as_ref()else{return Ok(None);};
                    let grant=document.agent_local_check_access(WINDOW)?.access;
                    let mut r=self.record().ok_or_else(bad)?;let c=r.cli.as_mut().ok_or_else(bad)?;
                    if p.agent_local_check.as_ref()!=c.origin.as_ref(){return Err(bad());}
                    if matches!(p.phase,offline::Phase::Starting|offline::Phase::Running|offline::Phase::Stopping){None}
                    else{
                        let done=completed(p,c.origin.as_ref().ok_or_else(bad)?,&project).map_err(|_|bad())?;
                        if !grant.consumed||grant.project_id.as_ref()!=c.project.as_ref()||grant.observation_revision!=c.revision{return Err(bad());}
                        c.consumed=true;
                        c.files.send(&json!({"phase":"terminal","operationId":done.operation,"ownerGeneration":done.generation,
                            "reportSha256":done.digest})).map_err(|_|bad())?;
                        c.completed=Some(done);Some(Step::Checked)
                    }
                },
                Step::Checked=>{
                    let value={let mut r=self.record().ok_or_else(bad)?;r.cli.as_mut().ok_or_else(bad)?.files.poll(1,"checked").map_err(|_|bad())?};
                    if let Some(v)=value {
                        let status=document.offline_preflight_status()?;
                        {let r=self.record().ok_or_else(bad)?;let c=r.cli.as_ref().ok_or_else(bad)?;
                            c.same(status.operation.as_ref().ok_or_else(bad)?,&project).map_err(|_|bad())?;
                            if !keys(&v,&["phase","origin","reportSha256"])||v["origin"]!=json!(c.origin)
                                ||v["reportSha256"]!=c.completed.as_ref().ok_or_else(bad)?.digest{return Err(bad());}}
                        let local=document.revoke_agent_local_check(WINDOW)?.access;
                        let read=document.revoke_application_read()?;
                        if local.enabled||read.enabled{return Err(bad());}
                        let mut r=self.record().ok_or_else(bad)?;let c=r.cli.as_mut().ok_or_else(bad)?;
                        c.checked=true;c.revoked=true;c.files.send(&json!({"phase":"revoked"})).map_err(|_|bad())?;
                        Some(Step::Denied)
                    }else{None}
                },
                Step::Denied=>{
                    let value={let mut r=self.record().ok_or_else(bad)?;r.cli.as_mut().ok_or_else(bad)?.files.poll(2,"denied").map_err(|_|bad())?};
                    if let Some(v)=value {
                        if v!=json!({"phase":"denied"}){return Err(bad());}
                        let path=self.record().and_then(|r|r.cli.as_ref()?.files.application().ok()).ok_or_else(bad)?;
                        // READ re-Allow performs its own actual fresh snapshot.
                        // It does not authorize a second execution or replay.
                        let checked=document.application_read_status()?;
                        let read=document.allow_application_read(&project,checked.permission_revision,&path).await?;
                        let local=document.agent_local_check_access(WINDOW)?.access;
                        if !read.enabled||read.remaining_ms==0||local.enabled||read.project_ids.len()!=1{return Err(bad());}
                        let status=document.offline_preflight_status()?;
                        let mut r=self.record().ok_or_else(bad)?;let c=r.cli.as_mut().ok_or_else(bad)?;
                        if read.project_ids.first()!=c.project.as_ref(){return Err(bad());}
                        c.same(status.operation.as_ref().ok_or_else(bad)?,&project).map_err(|_|bad())?;
                        c.reallowed=true;c.files.send(&json!({"phase":"reallowed"})).map_err(|_|bad())?;Some(Step::Done)
                    }else{None}
                },
                Step::Done=>{
                    let value={let mut r=self.record().ok_or_else(bad)?;r.cli.as_mut().ok_or_else(bad)?.files.poll(3,"done").map_err(|_|bad())?};
                    if let Some(v)=value {
                        let status=document.offline_preflight_status()?;
                        if document.agent_local_check_access(WINDOW)?.access.enabled{return Err(bad());}
                        let mut r=self.record().ok_or_else(bad)?;
                        {let c=r.cli.as_mut().ok_or_else(bad)?;
                            c.same(status.operation.as_ref().ok_or_else(bad)?,&project).map_err(|_|bad())?;
                            if !keys(&v,&["phase","origin","reportSha256"])||v["origin"]!=json!(c.origin)
                                ||v["reportSha256"]!=c.completed.as_ref().ok_or_else(bad)?.digest{return Err(bad());}}
                        r.fixture.verify(false).map_err(|_|bad())?;
                        let c=r.cli.as_mut().ok_or_else(bad)?;c.readback=true;c.driver_done=true;
                        c.files.close().map_err(|_|bad())?;
                        r.file_readback=true;r.step=OuterStep::Close;None
                    }else{None}
                },
            })
        }.await;
        match result {
            Ok(Some(next)) => {
                if let Some(mut r) = self.record() {
                    if r.step == OuterStep::Cli(step) {
                        r.step = OuterStep::Cli(next)
                    } else {
                        self.fail_with("installed-cli-original-contract");
                    }
                }
            }
            Ok(None) => {}
            Err(_) => self.fail_with("installed-cli-original-contract"),
        }
    }
    /// Called once with the actual report returned by the existing Host
    /// shutdown, after its worker joins. There is no second shutdown request.
    pub(crate) fn cli_host_shutdown(
        &self,
        report: &crate::application_service_host::HostShutdownReport,
    ) -> bool {
        if self.case != Case::Cli {
            return true;
        }
        let Some(mut r) = self.record() else {
            return false;
        };
        let Some(c) = r.cli.as_mut() else {
            return false;
        };
        if !c.driver_done
            || !c.readback
            || !c.files.closed()
            || c.host.is_some()
            || !host_return(
                report.settled(),
                report.failures.is_empty(),
                report.workers_joined,
            )
        {
            self.fail_with("installed-cli-original-contract");
            return false;
        }
        c.host = report.workers_joined;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn projection() -> (offline::Projection, agent::Query) {
        let query: agent::Query = serde_json::from_value(json!({
            "serviceInstance":"1".repeat(32),"projectId":"2".repeat(32),"requestId":"3".repeat(32)
        }))
        .unwrap();
        let report = json!({"schemaVersion":1,"scope":"saved-local-android-project-checks",
            "usedConfig":config(),"findings":[
                {"ordinal":0,"check":"android-gradle-wrapper","message":"android-gradle-wrapper","status":"MISSING","projectCheckIndex":null},
                {"ordinal":1,"check":"version-source","message":"version-source","status":"PASS","projectCheckIndex":null},
                {"ordinal":2,"check":"workspace-private-output","message":"workspace-private-output","status":"PASS","projectCheckIndex":null}],
            "summary":{"total":3,"shown":3,"omitted":0,"counts":{"PASS":2,"FAIL":0,"MISSING":1,"BLOCKED":0,
                "INVALID":0,"SKIP":0,"MANUAL":0,"CONFIGURED":0,"NOT_APPLICABLE":0}},
            "limitations":["saved-inputs-not-atomic","project-code-effects-possible","not-network-isolated",
                "core-builds-disabled","artifact-validation-not-requested","toolkit-signing-credentials-store-not-requested",
                "release-readiness-not-assessed"]});
        (
            offline::Projection {
                agent_local_check: Some(query.clone()),
                operation_id: "4".repeat(32),
                owner_generation: "5".repeat(32),
                context: offline::Context {
                    project_id: "inert-project".into(),
                    draft_revision: 0,
                    baseline_generation: 1,
                    saved_config: offline::Content {
                        bytes: config().bytes,
                        sha256: config().sha256,
                    },
                    platform: offline::Platform::Android,
                    operation: offline::Operation::LocalProjectChecks,
                },
                phase: offline::Phase::Terminal,
                intent_usable: false,
                outcome: Some(offline::Outcome::Complete),
                reason: offline::Reason::None,
                result: Some(serde_json::from_value(report).unwrap()),
            },
            query,
        )
    }
    #[test]
    fn only_the_fixed_tool_image_accepts_the_cli_fixture() {
        assert!(selected(
            Some("installed-shell-observation"),
            Some("tool-setup"),
            true
        ));
        for scope in [None, Some("git-native"), Some("disabled"), Some(NAME)] {
            assert!(!selected(Some("installed-shell-observation"), scope, true));
        }
        assert!(!selected(Some("ordinary-image"), Some("tool-setup"), true));
        assert!(!selected(
            Some("installed-shell-observation"),
            Some("tool-setup"),
            false
        ));
        assert!(std::mem::size_of::<Record>() + 2 * 4096 + 3 * agent::REPORT_LIMIT < BACKING);
    }
    #[test]
    fn phase_data_cannot_replace_origin_or_actual_complete_report() {
        assert!(keys(
            &json!({"phase":"done","origin":{},"reportSha256":"a"}),
            &["phase", "origin", "reportSha256"]
        ));
        assert!(!keys(
            &json!({"phase":"done","origin":{},"reportSha256":"a","grant":true}),
            &["phase", "origin", "reportSha256"]
        ));
        assert_eq!(agent::CONSENT, "agent-saved-local-android-checks-v1");
        let config_value: Value = crate::protocol::strict_json(CONFIG).unwrap();
        for name in ["preflight", "androidArtifact", "iosArtifact"] {
            assert_eq!(config_value["projectChecks"][name], json!([]));
        }
        // Actual fixed native/driver phase shapes, including the full retained
        // origin, fit the pre-parse bound. No grant or native action runs here.
        let (p, query) = projection();
        let done = completed(&p, &query, "inert-project").unwrap();
        for value in [
            json!({"phase":"allowed","projectId":query.project_id,"revision":1,"config":config()}),
            json!({"phase":"submitted","origin":query,"revision":1}),
            json!({"phase":"terminal","operationId":done.operation,"ownerGeneration":done.generation,"reportSha256":done.digest}),
            json!({"phase":"checked","origin":query,"reportSha256":done.digest}),
            json!({"phase":"revoked"}),
            json!({"phase":"denied"}),
            json!({"phase":"reallowed"}),
            json!({"phase":"done","origin":query,"reportSha256":done.digest}),
        ] {
            let raw = serde_json::to_vec(&value).unwrap();
            let line = fixture::phase_line(&raw).unwrap();
            assert_eq!(crate::protocol::strict_json(line).unwrap(), value);
        }
        let mut boundary = br#"{"phase":"denied"}"#.to_vec();
        boundary.resize(fixture::PHASE_LINE_LIMIT, b' ');
        assert_eq!(fixture::PHASE_LINE_LIMIT, 512);
        assert_eq!(
            crate::protocol::strict_json(fixture::phase_line(&boundary).unwrap()).unwrap(),
            json!({"phase":"denied"})
        );
        boundary.push(b' ');
        assert!(fixture::phase_line(&boundary).is_err());
        assert!(fixture::phase_line(&[0xff; 513]).is_err());
        assert!(fixture::phase_line(b"").is_err());
    }
    #[test]
    fn only_same_terminal_projection_and_saved_config_match_the_fixture() {
        let (p, query) = projection();
        let good = completed(&p, &query, "inert-project").unwrap();
        assert_eq!(completed(&p, &query, "inert-project"), Ok(good));
        let mut changed = Vec::new();
        let mut q = p.clone();
        q.phase = offline::Phase::Running;
        changed.push(q);
        let mut q = p.clone();
        q.phase = offline::Phase::Unknown;
        changed.push(q);
        let mut q = p.clone();
        q.outcome = Some(offline::Outcome::Refused);
        changed.push(q);
        let mut q = p.clone();
        q.reason = offline::Reason::CleanupUnknown;
        changed.push(q);
        let mut q = p.clone();
        q.intent_usable = true;
        changed.push(q);
        let mut q = p.clone();
        q.context.saved_config.sha256 = "f".repeat(64);
        changed.push(q);
        let mut q = p.clone();
        q.context.operation = offline::Operation::OfflinePreflight;
        changed.push(q);
        let mut q = p.clone();
        q.context.baseline_generation = 2;
        changed.push(q);
        let mut q = p.clone();
        q.agent_local_check = None;
        changed.push(q);
        let mut q = p.clone();
        q.result = None;
        changed.push(q);
        for q in changed {
            assert!(completed(&q, &query, "inert-project").is_err());
        }
        assert!(completed(&p, &query, "another-project").is_err());
        let mut foreign = query.clone();
        foreign.request_id = crate::service_protocol::Id::parse(&"6".repeat(32)).unwrap();
        assert!(completed(&p, &foreign, "inert-project").is_err());
    }
    #[test]
    fn late_stop_comparison_keeps_full_original_report_not_just_pass_count() {
        let (p, query) = projection();
        let original = completed(&p, &query, "inert-project").unwrap();
        // A same finished projection is compatible with late STOP. No STOP
        // operation is executed by this DATA test.
        assert_eq!(
            completed(&p.clone(), &query, "inert-project").unwrap(),
            original
        );
        let mut value = serde_json::to_value(p.result.as_ref().unwrap()).unwrap();
        value["findings"][2]["status"] = json!("CONFIGURED");
        value["summary"]["counts"]["PASS"] = json!(1);
        value["summary"]["counts"]["CONFIGURED"] = json!(1);
        let mut q = p.clone();
        q.result = Some(serde_json::from_value(value).unwrap());
        // This would lose the required workspace PASS and cannot count as the journey.
        assert!(completed(&q, &query, "inert-project").is_err());
        let mut q = p.clone();
        q.owner_generation = "6".repeat(32);
        assert_ne!(completed(&q, &query, "inert-project").unwrap(), original);
    }
    #[test]
    fn canonical_report_comparison_is_independent_of_map_insertion_order() {
        let a: Value = serde_json::from_str(r#"{"z":[{"b":2,"a":1}],"a":false}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":false,"z":[{"a":1,"b":2}]}"#).unwrap();
        assert_eq!(canonical(a), canonical(b));
        assert!(canonical(json!({"oversized":"x".repeat(FIXTURE_REPORT_LIMIT)})).is_err());
    }
    #[test]
    fn actual_host_return_needs_all_eight_ipc_workers_and_no_close_failure() {
        assert!(host_return(true, true, Some(8)));
        for count in [None, Some(0), Some(7), Some(9)] {
            assert!(!host_return(true, true, count));
        }
        assert!(!host_return(false, true, Some(8)));
        assert!(!host_return(true, false, Some(8)));
        // Seven CLI processes are not seven IPC joins: Submit also sends Info.
        assert_ne!(7, 8);
    }
}
