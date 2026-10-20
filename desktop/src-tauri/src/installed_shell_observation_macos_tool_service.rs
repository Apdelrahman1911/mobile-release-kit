//! One explicitly selected, nonshipping prerequisite. The three tool journeys
//! remain Check-only. All work uses the existing Document/Saved service owner.
use super::{build, registration as wire, BridgeError, Control, DocumentBinding, Observation};
use serde_json::{json, Value};
use std::sync::Arc;

pub(super) const NAME: &str = "tool-service-prerequisite";
pub(super) const SECONDS: u64 = 750;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Request,
    RequestWait,
    Check,
    CheckWait,
    Finish,
}

#[derive(Clone)]
struct Binding {
    id: String,
    generation: u32,
    source_generation: u32,
    action: wire::ServiceAction,
    context: build::Prepare,
}
impl Binding {
    fn capture(status: &wire::ServiceStatus, request: &wire::ServiceRequest) -> Option<Self> {
        let operation = status.operation.as_ref()?;
        (status.valid()
            && status.setup_generation == request.setup_generation.checked_add(1)?
            && operation.setup_generation == status.setup_generation
            && operation.source_generation == 0
            && operation.action == request.action
            && operation.context == request.context)
            .then(|| Self {
                id: operation.operation_id.clone(),
                generation: operation.setup_generation,
                source_generation: operation.source_generation,
                action: operation.action,
                context: operation.context.clone(),
            })
    }
    fn matches(&self, status: &wire::ServiceStatus) -> bool {
        status.valid()
            && status.setup_generation == self.generation
            && status.operation.as_ref().is_some_and(|operation| {
                operation.operation_id == self.id
                    && operation.setup_generation == self.generation
                    && operation.source_generation == self.source_generation
                    && operation.action == self.action
                    && operation.context == self.context
            })
    }
    fn bytes(&self) -> Option<usize> {
        self.id.capacity().checked_add(self.context.retained_heap_bytes()?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Finding { Ready, Approval, Denied, Missing, Unavailable }
impl Finding {
    fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready", Self::Approval => "approval-required",
            Self::Denied => "approval-denied", Self::Missing => "service-not-found",
            Self::Unavailable => "service-unavailable",
        }
    }
}
fn pending(phase: wire::ServicePhase) -> bool {
    matches!(phase, wire::ServicePhase::Checking | wire::ServicePhase::Requesting | wire::ServicePhase::Settling)
}
// Only a status returned by the actual Document can reach this comparison.
// Native retirement/finalization already gates its Complete/Refused publication.
// This parser never constructs an owner, Ready, permit, or disposal proof.
fn terminal(status: &wire::ServiceStatus, action: wire::ServiceAction) -> Option<Finding> {
    if !status.valid()
        || !matches!(status.phase, wire::ServicePhase::Complete | wire::ServicePhase::Refused)
        || !matches!(status.reason, wire::Reason::None | wire::Reason::ApprovalDenied
            | wire::Reason::ServiceUnavailable | wire::Reason::SigningUnavailable)
    { return None; }
    let observed = status.observation?;
    if !observed.native_settled || observed.mutation_uncertain { return None; }
    if status.phase == wire::ServicePhase::Complete && status.reason == wire::Reason::None
        && status.prerequisite == wire::Prerequisite::Ready && observed.state == wire::ServiceState::Enabled
        && match action {
            wire::ServiceAction::RequestRegistration => matches!(observed.outcome,
                wire::ServiceOutcome::RegistrationRequested | wire::ServiceOutcome::AlreadyRegistered),
            wire::ServiceAction::Check => observed.outcome == wire::ServiceOutcome::Observed
                && !observed.mutation_entered && !observed.mutation_returned,
            wire::ServiceAction::OpenApprovalSettings => false,
        }
    { return Some(Finding::Ready); }
    if status.reason == wire::Reason::ApprovalDenied || observed.outcome == wire::ServiceOutcome::DeniedByUser {
        Some(Finding::Denied)
    } else if observed.state == wire::ServiceState::RequiresApproval { Some(Finding::Approval) }
    else if observed.state == wire::ServiceState::NotFound { Some(Finding::Missing) }
    else if matches!(observed.state, wire::ServiceState::NotRegistered | wire::ServiceState::Unavailable | wire::ServiceState::Error)
        || matches!(status.reason, wire::Reason::ServiceUnavailable | wire::Reason::SigningUnavailable) {
        Some(Finding::Unavailable)
    } else { None }
}

#[derive(Default)]
pub(super) struct Record {
    request_called: bool,
    check_called: bool,
    request: Option<Binding>,
    check: Option<Binding>,
    request_settled: bool,
    check_settled: bool,
    finding: Option<Finding>,
    nonentry: bool,
}
impl Record {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.request.iter().chain(self.check.iter()).try_fold(0usize, |n, value| n.checked_add(value.bytes()?))
    }
    fn claim(&mut self, action: wire::ServiceAction) -> bool {
        match action {
            wire::ServiceAction::RequestRegistration if !self.request_called && !self.check_called
                && self.request.is_none() && self.check.is_none() && self.finding.is_none() && !self.nonentry => {
                self.request_called = true; true
            },
            wire::ServiceAction::Check if self.request_called && self.request_settled
                && self.request.is_some() && self.finding == Some(Finding::Ready) && !self.nonentry
                && !self.check_called && self.check.is_none() => {self.check_called = true; true},
            _ => false,
        }
    }
    fn complete(&self) -> bool {
        if !self.request_called || self.finding.is_none()
            || self.request_settled != self.request.is_some() || self.check_settled != self.check.is_some()
            || (self.check_called && !self.request_settled) || (self.check.is_some() && !self.check_called) {
            return false;
        }
        if self.nonentry {
            self.finding == Some(Finding::Unavailable) &&
                ((!self.request_settled && !self.check_called && !self.check_settled)
                    || (self.request_settled && self.check_called && !self.check_settled))
        } else {
            self.request_settled && (!self.check_called || self.check_settled)
                && (self.finding != Some(Finding::Ready) || self.check_settled)
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.complete() && !self.nonentry && self.finding == Some(Finding::Ready)
            && self.check_called && self.check_settled
    }
    pub(super) fn report(&self, control: &Control, normal_quit: bool) -> Option<Value> {
        if !normal_quit || !control.completed() || !self.complete()
            || control.unexecuted.load(super::Ordering::SeqCst) == self.ready() { return None; }
        Some(json!({"mechanism":"same-original-tool-service-prerequisite-v1",
            "execution":if self.ready(){"ready"}else{"not-executed-prerequisite"},
            "finding":self.finding?.name(),"requestCalls":u8::from(self.request_called),
            "checkCalls":u8::from(self.check_called),"requestAdmitted":self.request.is_some(),
            "checkAdmitted":self.check.is_some(),"requestSettled":self.request_settled,
            "checkSettled":self.check_settled,"knownNonentry":self.nonentry,
            "sameOriginalBindings":true,"normalQuitOriginal":2,"allOriginalsSettled":true,
            "projectSentinelPreserved":true,"sourceInputsRead":false,"toolAcquisitionEntered":false,
            "settingsOpened":false,"serviceUnregistered":false,"productionQualified":false}))
    }
}

fn record<T>(q: &Observation, f: impl FnOnce(&mut Record) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
    let mut r = q.record().ok_or_else(BridgeError::invalid)?;
    f(&mut r.tool_setup.as_mut().ok_or_else(BridgeError::invalid)?.service)
}
fn known_nonentry(error: &BridgeError) -> bool { error.code == "android_service_unavailable" }

fn bind_return(q: &Observation, result: Result<wire::ServiceStatus, BridgeError>, request: wire::ServiceRequest) -> Result<super::Step, BridgeError> {
    let check = request.action == wire::ServiceAction::Check;
    match result {
        Err(error) if known_nonentry(&error) => {
            // This exact error is the existing pre-admission contract. Lost
            // release/status replies are service_unconfirmed, never nonentry.
            record(q, |r| {r.nonentry = true; r.finding = Some(Finding::Unavailable); Ok(())})?;
            Ok(super::Step::Prerequisite(Step::Finish))
        },
        Err(error) => Err(error),
        Ok(status) => {
            let binding = Binding::capture(&status, &request).ok_or_else(BridgeError::invalid)?;
            record(q, |r| {
                if check {
                    if r.check.is_some() || r.request.as_ref().is_none_or(|prior| prior.id == binding.id) { return Err(BridgeError::invalid()); }
                    r.check = Some(binding);
                } else {
                    if r.request.is_some() { return Err(BridgeError::invalid()); }
                    r.request = Some(binding);
                }
                Ok(())
            })?;
            Ok(super::Step::Prerequisite(if check {Step::CheckWait} else {Step::RequestWait}))
        },
    }
}

pub(super) async fn tick(q: &Arc<Observation>, document: &DocumentBinding, step: Step) -> Result<Option<super::Step>, BridgeError> {
    let invalid = BridgeError::invalid;
    let control = q.tool_setup.as_ref().filter(|c| c.case() == super::Case::ServicePreparation).ok_or_else(invalid)?;
    let context = || q.record().and_then(|r| r.tool_setup.as_ref()?.context.clone()).ok_or_else(invalid);
    Ok(match step {
        Step::Request => {
            let before = document.android_tool_service_status()?;
            if !before.valid() || before.setup_generation != 0 || before.operation.is_some() { return Err(invalid()); }
            let request = wire::ServiceRequest::request_registration(&serde_json::to_vec(&json!({
                "schemaVersion":1,"setupGeneration":before.setup_generation,"context":context()?,
                "consentVersion":wire::SERVICE_CONSENT,"registrationAcknowledged":true})).map_err(|_|invalid())?)?;
            record(q, |r| r.claim(wire::ServiceAction::RequestRegistration).then_some(()).ok_or_else(invalid))?;
            Some(bind_return(q, document.android_tool_service_action(request.clone()), request)?)
        },
        Step::RequestWait | Step::CheckWait => {
            let check = step == Step::CheckWait;
            let status = document.android_tool_service_status()?;
            let binding = record(q, |r| (if check {&r.check}else{&r.request}).clone().ok_or_else(invalid))?;
            if !binding.matches(&status) { return Err(invalid()); }
            if pending(status.phase) { None } else {
                let finding = terminal(&status,binding.action).ok_or_else(invalid)?;
                record(q, |r| {
                    if check {if r.check_settled{return Err(invalid());} r.check_settled=true;}
                    else {if r.request_settled{return Err(invalid());} r.request_settled=true;}
                    r.finding=Some(finding); Ok(())
                })?;
                Some(super::Step::Prerequisite(if !check && finding==Finding::Ready {Step::Check}else{Step::Finish}))
            }
        },
        Step::Check => {
            let prior = record(q, |r| {
                if !r.request_settled || r.check_called || r.finding != Some(Finding::Ready) {return Err(invalid());}
                r.request.clone().ok_or_else(invalid)
            })?;
            let fresh = document.installed_tool_setup_saved(&prior.context.project_id).await?;
            if !q.timely() {return Err(invalid());}
            let before = document.android_tool_service_status()?;
            if !prior.matches(&before) || pending(before.phase) {return Err(invalid());}
            let request = wire::ServiceRequest::check(&serde_json::to_vec(&json!({
                "schemaVersion":1,"setupGeneration":before.setup_generation,"context":fresh})).map_err(|_|invalid())?)?;
            record(q, |r| r.claim(wire::ServiceAction::Check).then_some(()).ok_or_else(invalid))?;
            Some(bind_return(q, document.android_tool_service_action(request.clone()), request)?)
        },
        Step::Finish => {
            let ready = record(q, |r| if r.complete(){Ok(r.ready())}else{Err(invalid())})?;
            q.tool_verify().map_err(|_|invalid())?;
            if !control.finish_service(ready) { return Err(invalid()); }
            let mut r=q.record().ok_or_else(invalid)?;
            if r.step!=super::OuterStep::ToolSetup(super::Step::Prerequisite(step)) || r.pending.is_some() {return Err(invalid());}
            r.file_readback=true; r.step=super::OuterStep::Close; None
        },
    })
}

// Called by the existing harness=false observer's inert startup contracts.
// No service, account, filesystem, Control, native owner or Ready is created.
pub(super) fn data_checks() -> bool {
    let Ok(context) = build::prepare(&json!({"projectId":"project-a","draftRevision":0,"baselineGeneration":1,
        "savedConfig":{"bytes":1,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"VERSION","bytes":1,"sha256":"b".repeat(64),"name":"1.0","build":1},
        "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})) else {return false;};
    let request = wire::ServiceRequest {setup_generation:0,context:context.clone(),action:wire::ServiceAction::RequestRegistration};
    let mut status = wire::ServiceStatus {schema_version:1,status_revision:1,setup_generation:1,
        availability:build::Availability::Available,prerequisite:wire::Prerequisite::Ready,
        phase:wire::ServicePhase::Complete,reason:wire::Reason::None,
        operation:Some(wire::ServiceOperation {operation_id:"c".repeat(32),setup_generation:1,source_generation:0,
            action:request.action,context}),
        observation:Some(wire::ServiceObservation {state:wire::ServiceState::Enabled,outcome:wire::ServiceOutcome::AlreadyRegistered,
            mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true})};
    let Some(binding)=Binding::capture(&status,&request) else {return false;};
    if !binding.matches(&status) || terminal(&status,request.action)!=Some(Finding::Ready) {return false;}
    let mut record=Record::default();
    if !record.claim(request.action) || record.claim(request.action) || record.claim(wire::ServiceAction::Check)
        || record.complete() {return false;}
    record.request=Some(binding.clone());record.request_settled=true;record.finding=Some(Finding::Ready);
    if record.complete() || !record.claim(wire::ServiceAction::Check) || record.claim(wire::ServiceAction::Check)
        || record.claim(request.action) || record.complete() {return false;}
    record.nonentry=true;record.finding=Some(Finding::Unavailable);
    if !record.complete() || record.ready() {return false;}
    for code in ["android_service_unconfirmed","cleanup_unknown","query_timeout","protocol_error"] {
        if known_nonentry(&BridgeError::new(code,"inert")) {return false;}
    }
    if !known_nonentry(&BridgeError::new("android_service_unavailable","inert")) {return false;}
    status.operation.as_mut().unwrap().context.draft_revision+=1;
    if binding.matches(&status) || Binding::capture(&status,&request).is_some() {return false;}
    status.operation.as_mut().unwrap().context=request.context.clone();
    status.phase=wire::ServicePhase::Unknown;status.reason=wire::Reason::CleanupUnknown;
    status.availability=build::Availability::CleanupUnknown;status.observation=None;
    if terminal(&status,request.action).is_some() {return false;}
    status.phase=wire::ServicePhase::Refused;status.reason=wire::Reason::ApprovalDenied;
    status.availability=build::Availability::Available;status.prerequisite=wire::Prerequisite::ApprovalDenied;
    status.observation=Some(wire::ServiceObservation {state:wire::ServiceState::RequiresApproval,outcome:wire::ServiceOutcome::DeniedByUser,
        mutation_entered:true,mutation_returned:true,mutation_uncertain:false,native_settled:true});
    terminal(&status,request.action)==Some(Finding::Denied)
}
