//! One explicitly selected, nonshipping prerequisite. The three tool journeys
//! remain Check-only. All work uses the existing Document/Saved service owner.
use super::{build, registration as wire, BridgeError, Control, DocumentBinding, Observation};
use serde::Serialize;
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
    // STOP is still the SAME live original, not a terminal observation. Its
    // existing coordinator/deadline must establish final settlement first.
    matches!(phase, wire::ServicePhase::Checking | wire::ServicePhase::Requesting
        | wire::ServicePhase::Settling | wire::ServicePhase::Stopping)
}
// Only a status returned by the actual Document can reach this comparison.
// Native retirement/finalization already gates its Complete/Refused publication.
// This parser never constructs an owner, Ready, permit, or disposal proof.
fn terminal(status: &wire::ServiceStatus, action: wire::ServiceAction) -> Option<Finding> {
    if !status.valid()
        || !matches!(status.phase, wire::ServicePhase::Complete | wire::ServicePhase::Refused)
        || !matches!(status.reason, wire::Reason::None | wire::Reason::ApprovalRequired | wire::Reason::ApprovalDenied
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

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Validation { BeforeRequest, AdmissionBinding, WaitBinding, Terminal, BeforeCheck }

// Failure-only projection of an ALREADY returned status. No context, project,
// operation IDs, native query, authority or replacement settlement is retained.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FailureSample {
    validation: Validation,
    status_valid: bool,
    phase: wire::ServicePhase,
    reason: wire::Reason,
    prerequisite: wire::Prerequisite,
    observation: Option<wire::ServiceObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_failure: Option<wire::ServiceIdentityFailure>,
}
impl FailureSample {
    fn capture(validation: Validation, status: &wire::ServiceStatus) -> Self {
        Self { validation, status_valid: status.valid(), phase: status.phase,
            reason: status.reason, prerequisite: status.prerequisite, observation: status.observation,
            identity_failure: status.identity_failure }
    }
    pub(crate) fn matches(self, step: super::Step) -> bool {
        let super::Step::Prerequisite(step) = step else { return false; };
        match self.validation {
            Validation::BeforeRequest => step == Step::Request,
            Validation::AdmissionBinding => matches!(step, Step::Request | Step::Check),
            Validation::WaitBinding | Validation::Terminal => matches!(step, Step::RequestWait | Step::CheckWait),
            Validation::BeforeCheck => step == Step::Check,
        }
    }
    pub(crate) fn value(self) -> Value { json!(self) }
    fn terminal_value(self)->Value {
        let mut value=self.value();
        if let Some((accepted,error))=self.observation.and_then(|value|value.registration_return) {
            value["registrationReturn"]=json!({"accepted":accepted,"error":error});
        }
        value
    }
    fn permits_fresh_check(self) -> bool {
        matches!(self.validation, Validation::Terminal) && self.status_valid
            && self.phase == wire::ServicePhase::Refused
            && self.reason == wire::Reason::ServiceUnavailable
            && self.prerequisite == wire::Prerequisite::ServiceUnavailable
            && self.observation.is_some_and(|observed| observed.outcome == wire::ServiceOutcome::Error
                && observed.mutation_entered && observed.mutation_returned
                && !observed.mutation_uncertain && observed.native_settled
                && observed.registration_return.is_some_and(|(accepted, _)| !accepted))
    }
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
    pub(super) failure: Option<FailureSample>,
    terminal: Option<FailureSample>,
    request_terminal: Option<FailureSample>,
}
impl Record {
    fn check_allowed(&self) -> bool {
        self.request_called && self.request_settled && self.request.is_some() && !self.nonentry
            && !self.check_called && self.check.is_none()
            && (self.finding == Some(Finding::Ready)
                || self.request_terminal.is_some_and(FailureSample::permits_fresh_check))
    }
    fn settle(&mut self, check: bool, sample: FailureSample, finding: Finding) -> Option<Step> {
        if check {
            if !self.check_called || self.check.is_none() || self.check_settled || !self.request_settled {return None;}
            self.check_settled=true;
        } else {
            if !self.request_called || self.request.is_none() || self.request_settled || self.check_called {return None;}
            self.request_settled=true;
        }
        // A separately admitted read-only Check can describe current state,
        // but cannot turn the failed Request into a Ready witness.
        self.finding=Some(if check && self.request_terminal.is_some() && finding==Finding::Ready {
            Finding::Unavailable
        } else {finding});
        self.terminal=Some(sample);
        if !check && sample.permits_fresh_check() {self.request_terminal=Some(sample);}
        Some(if !check && self.check_allowed() {Step::Check}else{Step::Finish})
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.request.iter().chain(self.check.iter()).try_fold(0usize, |n, value| n.checked_add(value.bytes()?))
    }
    fn claim(&mut self, action: wire::ServiceAction) -> bool {
        match action {
            wire::ServiceAction::RequestRegistration if !self.request_called && !self.check_called
                && self.request.is_none() && self.check.is_none() && self.finding.is_none() && !self.nonentry => {
                self.request_called = true; true
            },
            wire::ServiceAction::Check if self.check_allowed() => {self.check_called = true; true},
            _ => false,
        }
    }
    fn complete(&self) -> bool {
        if !self.request_called || self.finding.is_none()
            || self.request_settled != self.request.is_some() || self.check_settled != self.check.is_some()
            || (self.check_called && !self.request_settled) || (self.check.is_some() && !self.check_called)
            || self.request_terminal.is_some_and(|sample| !sample.permits_fresh_check()
                || !self.request_settled || !self.check_called || self.finding == Some(Finding::Ready)) {
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
            && self.check_called && self.check_settled && self.request_terminal.is_none()
    }
    pub(super) fn report(&self, control: &Control, normal_quit: bool) -> Option<Value> {
        if !normal_quit || !control.completed() || !self.complete()
            || control.unexecuted.load(super::Ordering::SeqCst) == self.ready() { return None; }
        let mut value=json!({"mechanism":"same-original-tool-service-prerequisite-v1",
            "execution":if self.ready(){"ready"}else{"not-executed-prerequisite"},
            "finding":self.finding?.name(),"requestCalls":u8::from(self.request_called),
            "checkCalls":u8::from(self.check_called),"requestAdmitted":self.request.is_some(),
            "checkAdmitted":self.check.is_some(),"requestSettled":self.request_settled,
            "checkSettled":self.check_settled,"knownNonentry":self.nonentry,
            "sameOriginalBindings":true,"normalQuitOriginal":2,"allOriginalsSettled":true,
            "projectSentinelPreserved":true,"sourceInputsRead":false,"toolAcquisitionEntered":false,
            "settingsOpened":false,"serviceUnregistered":false,"productionQualified":false});
        if let Some(sample)=self.terminal {
            value["terminal"]=sample.terminal_value();
        }
        if let Some(sample)=self.request_terminal {
            value["requestTerminal"]=sample.terminal_value();
        }
        Some(value)
    }
}

fn record<T>(q: &Observation, f: impl FnOnce(&mut Record) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
    let mut r = q.record().ok_or_else(BridgeError::invalid)?;
    f(&mut r.tool_setup.as_mut().ok_or_else(BridgeError::invalid)?.service)
}
fn known_nonentry(error: &BridgeError) -> bool { error.code == "android_service_unavailable" }

fn status_failure(q: &Observation, validation: Validation, status: &wire::ServiceStatus) -> BridgeError {
    // The validation already failed. Optional DATA capture cannot replace its
    // error, query native state, wait, or create another diagnostic writer.
    let sample = FailureSample::capture(validation, status);
    if let Ok(mut record) = q.record.try_lock() {
        if let Some(tool) = record.tool_setup.as_mut() { tool.service.failure.get_or_insert(sample); }
    }
    BridgeError::invalid()
}

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
            let binding = Binding::capture(&status, &request)
                .ok_or_else(|| status_failure(q, Validation::AdmissionBinding, &status))?;
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
            if !before.valid() || before.setup_generation != 0 || before.operation.is_some() {
                return Err(status_failure(q, Validation::BeforeRequest, &before));
            }
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
            if !binding.matches(&status) { return Err(status_failure(q, Validation::WaitBinding, &status)); }
            if pending(status.phase) { None } else {
                let finding = terminal(&status,binding.action)
                    .ok_or_else(|| status_failure(q, Validation::Terminal, &status))?;
                let sample = FailureSample::capture(Validation::Terminal,&status);
                let next = record(q, |r| r.settle(check,sample,finding).ok_or_else(invalid))?;
                Some(super::Step::Prerequisite(next))
            }
        },
        Step::Check => {
            let prior = record(q, |r| {
                if !r.check_allowed() {return Err(invalid());}
                r.request.clone().ok_or_else(invalid)
            })?;
            let fresh = document.installed_tool_setup_saved(&prior.context.project_id).await?;
            if !q.timely() {return Err(invalid());}
            let before = document.android_tool_service_status()?;
            let current = FailureSample::capture(Validation::Terminal,&before);
            if !prior.matches(&before) || pending(before.phase)
                || record(q, |r| Ok(r.request_terminal.is_some() && !current.permits_fresh_check()))? {
                return Err(status_failure(q, Validation::BeforeCheck, &before));
            }
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
fn identity_failure_data_checks(before: &wire::ServiceStatus) -> bool {
    use wire::{ServiceIdentityAdmissionFailure as A, ServiceIdentityFailure as F,
        ServiceIdentitySigningPhase as P, ServiceIdentitySigningResult as R};
    let at=std::time::Instant::now();
    let later=at+std::time::Duration::from_nanos(1);
    let first=F::Installation{reason:crate::installation::CheckReason::PayloadMismatch};
    let mut diagnostic=wire::ServiceIdentityDiagnostic::default();
    diagnostic.capture(first,wire::Reason::SigningUnavailable,at);
    diagnostic.capture(F::Recheck{reason:A::Identity},wire::Reason::SigningUnavailable,later);
    if diagnostic.for_first(Some((wire::Reason::SigningUnavailable,at)))!=Some(first)
        || diagnostic.for_first(Some((wire::Reason::SigningUnavailable,later))).is_some()
        || diagnostic.for_first(Some((wire::Reason::Cancelled,at))).is_some()
        || diagnostic.for_first(None).is_some() {return false;}
    let mut status=before.clone();status.phase=wire::ServicePhase::Refused;
    status.reason=wire::Reason::SigningUnavailable;status.prerequisite=wire::Prerequisite::SigningUnavailable;
    status.observation=None;
    let Ok(baseline)=serde_json::to_value(&status)else{return false;};
    for (failure,expected) in [
        (F::Profile,json!({"stage":"profile"})),
        (first,json!({"stage":"installation","reason":"payload-mismatch"})),
        (F::FixedPayload{reason:A::Ownership},json!({"stage":"fixed-payload","reason":"ownership"})),
        (F::Recheck{reason:A::Identity},json!({"stage":"recheck","reason":"identity"})),
        (F::NativeSigning{result:R::Refused,phase:Some(P::Inspect5),native_failed:true},
            json!({"stage":"native-signing","result":"refused","phase":"inspect-5","nativeFailed":true})),
        (F::NativeSigning{result:R::Unknown,phase:None,native_failed:false},
            json!({"stage":"native-signing","result":"unknown","phase":null,"nativeFailed":false})),
    ] {
        status.identity_failure=Some(failure);
        let sample=FailureSample::capture(Validation::Terminal,&status);
        if !status.valid() || status.clone().bounded().is_err()
            || terminal(&status,wire::ServiceAction::RequestRegistration).is_some()
            || serde_json::to_value(&status).ok()!=Some(baseline.clone())
            || sample.value()["identityFailure"]!=expected
            || !super::super::tool_service_failure_data_checks(sample,
                [Step::Request,Step::RequestWait,Step::Check,Step::CheckWait,Step::Finish].map(super::Step::Prerequisite)) {return false;}
    }
    status.identity_failure=None;
    FailureSample::capture(Validation::Terminal,&status).value().get("identityFailure").is_none()
}
pub(super) fn data_checks() -> bool {
    let Ok(context) = build::prepare(&json!({"projectId":"project-a","draftRevision":0,"baselineGeneration":1,
        "savedConfig":{"bytes":1,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"VERSION","bytes":1,"sha256":"b".repeat(64),"name":"1.0","build":1},
        "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})) else {return false;};
    let request = wire::ServiceRequest {setup_generation:0,context:context.clone(),action:wire::ServiceAction::RequestRegistration};
    let mut status = wire::ServiceStatus {schema_version:1,status_revision:1,setup_generation:1,
        availability:build::Availability::Available,prerequisite:wire::Prerequisite::Ready,
        phase:wire::ServicePhase::Complete,reason:wire::Reason::None,
        identity_failure:None,
        operation:Some(wire::ServiceOperation {operation_id:"c".repeat(32),setup_generation:1,source_generation:0,
            action:request.action,context}),
        observation:Some(wire::ServiceObservation {registration_return:None,state:wire::ServiceState::Enabled,outcome:wire::ServiceOutcome::AlreadyRegistered,
            mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true})};
    let Some(binding)=Binding::capture(&status,&request) else {return false;};
    if !binding.matches(&status) || terminal(&status,request.action)!=Some(Finding::Ready)
        || !identity_failure_data_checks(&status) {return false;}
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
    if !status.valid() || pending(status.phase) || terminal(&status,request.action).is_some() {return false;}
    let unknown = FailureSample::capture(Validation::Terminal, &status);
    if unknown.value() != json!({"validation":"terminal","statusValid":true,"phase":"unknown",
        "reason":"cleanup-unknown","prerequisite":"ready","observation":null})
        || !super::super::tool_service_failure_data_checks(unknown,
            [Step::Request,Step::RequestWait,Step::Check,Step::CheckWait,Step::Finish].map(super::Step::Prerequisite)) {return false;}
    for (validation, allowed) in [(Validation::BeforeRequest,[true,false,false,false,false]),
        (Validation::AdmissionBinding,[true,false,true,false,false]),
        (Validation::WaitBinding,[false,true,false,true,false]),
        (Validation::Terminal,[false,true,false,true,false]),
        (Validation::BeforeCheck,[false,false,true,false,false])] {
        let sample=FailureSample::capture(validation,&status);
        for (step,expected) in [Step::Request,Step::RequestWait,Step::Check,Step::CheckWait,Step::Finish].into_iter().zip(allowed) {
            if sample.matches(super::Step::Prerequisite(step))!=expected {return false;}
        }
        if sample.matches(super::Step::Context) {return false;}
    }
    // Actual valid active-original STOP, then a separately valid settled
    // refusal. Neither STOP nor RequiresApproval is an enabled/Ready witness.
    status.phase=wire::ServicePhase::Stopping;status.reason=wire::Reason::ApprovalRequired;
    status.availability=build::Availability::Available;status.prerequisite=wire::Prerequisite::ApprovalRequired;
    if !status.valid() || !binding.matches(&status) || !pending(status.phase)
        || terminal(&status,request.action).is_some() {return false;}
    status.phase=wire::ServicePhase::Refused;
    status.observation=Some(wire::ServiceObservation {registration_return:None,state:wire::ServiceState::RequiresApproval,outcome:wire::ServiceOutcome::NeedsApproval,
        mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true});
    if !status.valid() || pending(status.phase) || terminal(&status,request.action)!=Some(Finding::Approval) {return false;}
    let mut approval=Record {request_called:true,request:Some(binding.clone()),request_settled:true,
        finding:Some(Finding::Approval),..Record::default()};
    if !approval.complete() || approval.ready() || approval.claim(wire::ServiceAction::Check) {return false;}
    let returned = FailureSample::capture(Validation::WaitBinding, &status);
    if returned.value() != json!({"validation":"wait-binding","statusValid":true,"phase":"refused","reason":"approval-required",
        "prerequisite":"approval-required",
        "observation":{"state":"requires-approval","outcome":"needs-approval","mutationEntered":false,"mutationReturned":false,
            "mutationUncertain":false,"nativeSettled":true}}) {return false;}
    status.observation.as_mut().unwrap().native_settled=false;
    let invalid=FailureSample::capture(Validation::Terminal,&status).value();
    if status.valid() || terminal(&status,request.action).is_some()
        || invalid["statusValid"]!=false || invalid["observation"]["nativeSettled"]!=false
        || invalid["prerequisite"]!="approval-required" {return false;}
    status.observation.as_mut().unwrap().native_settled=true;
    status.phase=wire::ServicePhase::Complete;status.reason=wire::Reason::None;
    if !status.valid() || terminal(&status,request.action)!=Some(Finding::Approval) {return false;}
    status.phase=wire::ServicePhase::Refused;status.reason=wire::Reason::ApprovalDenied;
    status.availability=build::Availability::Available;status.prerequisite=wire::Prerequisite::ApprovalDenied;
    status.observation=Some(wire::ServiceObservation {registration_return:None,state:wire::ServiceState::RequiresApproval,outcome:wire::ServiceOutcome::DeniedByUser,
        mutation_entered:true,mutation_returned:true,mutation_uncertain:false,native_settled:true});
    if terminal(&status,request.action)!=Some(Finding::Denied) {return false;}
    status.reason=wire::Reason::ServiceUnavailable;status.prerequisite=wire::Prerequisite::ServiceUnavailable;
    status.observation=Some(wire::ServiceObservation{state:wire::ServiceState::NotFound,
        outcome:wire::ServiceOutcome::Error,mutation_entered:true,mutation_returned:true,
        mutation_uncertain:false,native_settled:true,registration_return:Some((false,"job-plist-not-found"))});
    let sample=FailureSample::capture(Validation::Terminal,&status);
    terminal(&status,request.action)==Some(Finding::Missing)
        && sample.terminal_value()==json!({"validation":"terminal","statusValid":true,
            "phase":"refused","reason":"service-unavailable","prerequisite":"service-unavailable",
            "observation":{"state":"not-found","outcome":"error","mutationEntered":true,
                "mutationReturned":true,"mutationUncertain":false,"nativeSettled":true},
            "registrationReturn":{"accepted":false,"error":"job-plist-not-found"}})
        && sample.value().get("registrationReturn").is_none()
        && failed_request_check_data_checks(&status,&binding)
}

fn failed_request_check_data_checks(failed: &wire::ServiceStatus, binding: &Binding) -> bool {
    let sample=FailureSample::capture(Validation::Terminal,failed);
    if !sample.permits_fresh_check() {return false;}
    for (entered,returned,uncertain,settled,accepted) in [
        (false,false,false,true,false),(true,false,false,true,false),(true,true,true,true,false),
        (true,true,false,false,false),(true,true,false,true,true),
    ] {
        let mut bad=*sample.observation.as_ref().unwrap();
        bad.mutation_entered=entered;bad.mutation_returned=returned;
        bad.mutation_uncertain=uncertain;bad.native_settled=settled;
        bad.registration_return=Some((accepted,"service-error-code-1"));
        if (FailureSample{observation:Some(bad),..sample}).permits_fresh_check() {return false;}
    }
    for phase in [wire::ServicePhase::Stopping,wire::ServicePhase::Unknown,wire::ServicePhase::Complete] {
        if (FailureSample{phase,..sample}).permits_fresh_check() {return false;}
    }
    if (FailureSample{status_valid:false,..sample}).permits_fresh_check()
        || (FailureSample{validation:Validation::WaitBinding,..sample}).permits_fresh_check() {return false;}
    for enabled in [false,true] {
        let mut record=Record{request_called:true,request:Some(binding.clone()),..Record::default()};
        if record.settle(false,sample,Finding::Missing)!=Some(Step::Check)
            || record.complete() || !record.claim(wire::ServiceAction::Check)
            || record.claim(wire::ServiceAction::Check) || record.claim(wire::ServiceAction::RequestRegistration) {return false;}
        let mut check=failed.clone();
        let operation=check.operation.as_mut().unwrap();
        operation.operation_id="d".repeat(32);operation.action=wire::ServiceAction::Check;
        operation.setup_generation+=1;check.setup_generation+=1;
        check.phase=if enabled{wire::ServicePhase::Complete}else{wire::ServicePhase::Refused};
        check.reason=if enabled{wire::Reason::None}else{wire::Reason::ApprovalRequired};
        check.prerequisite=if enabled{wire::Prerequisite::Ready}else{wire::Prerequisite::ApprovalRequired};
        check.observation=Some(wire::ServiceObservation{state:if enabled{wire::ServiceState::Enabled}else{wire::ServiceState::RequiresApproval},
            outcome:wire::ServiceOutcome::Observed,mutation_entered:false,mutation_returned:false,
            mutation_uncertain:false,native_settled:true,registration_return:None});
        let request=wire::ServiceRequest{setup_generation:failed.setup_generation,context:binding.context.clone(),action:wire::ServiceAction::Check};
        let Some(next)=Binding::capture(&check,&request)else{return false;};
        if next.id==binding.id || binding.matches(&check) {return false;}
        record.check=Some(next);
        let Some(finding)=terminal(&check,wire::ServiceAction::Check)else{return false;};
        if record.settle(true,FailureSample::capture(Validation::Terminal,&check),finding)!=Some(Step::Finish)
            || !record.complete() || record.ready() || record.request_terminal.unwrap().terminal_value()!=sample.terminal_value()
            || record.finding!=Some(if enabled{Finding::Unavailable}else{Finding::Approval})
            || record.settle(true,sample,Finding::Missing).is_some() {return false;}
        record.finding=Some(Finding::Ready);
        if record.complete() || record.ready() {return false;}
    }
    true
}
