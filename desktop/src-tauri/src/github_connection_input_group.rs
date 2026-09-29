//! Finite P2 operations over the ORIGINAL ConnectionState credential and clocks.
use super::*;
use std::sync::Arc;
use crate::{asset_session::{GitHubInputGoGate,GitHubInputMaterial},asset_source::RegisteredRoot,
    github_input_group_protocol as p,github_input_group_session as s,
    github_runner_prerequisite_protocol as rp,github_runner_prerequisite_session as rs,
    supervisor::{GitHubInputGroupReceipt,GitHubRunnerState,GitHubRunnerResult}};

// Public aggregation only. A decoded reply is not, by itself, a network
// cleanup receipt. The original native Settled caller supplies native_unknown.
fn completion_cleanup(network:Option<p::Settlement>,read_claimed:bool,native_unknown:bool) -> p::Settlement {
    if native_unknown {return p::Settlement::Unknown;}
    match network {
        Some(p::Settlement::Confirmed|p::Settlement::NotRun)=>p::Settlement::Confirmed,
        None if !read_claimed=>p::Settlement::Confirmed,
        _=>p::Settlement::Unknown,
    }
}

impl ConnectionState {
    pub(crate) fn input_material_settled(&self) -> bool { self.input.material_settled() }
    pub(crate) fn input_retirement_pending(&self) -> bool { self.input.retirement_pending() }
    pub(crate) fn input_memory_reserved(&self) -> bool { self.input.memory_reserved() }
    pub(crate) fn input_memory_capacity(&self) -> usize { self.input.memory_capacity() }
    pub(crate) fn input_work_pending(&self) -> bool { self.input.native_work_pending() }
    pub(crate) fn input_materials(&self) -> impl Iterator<Item=&Arc<GitHubInputMaterial>> { self.input.materials() }
    pub(crate) fn take_input_material_retirement(&mut self,document:&Arc<()>) -> s::MaterialRetirement { self.input.take_retirement(document) }
    pub(crate) fn finish_input_material_retirement(&mut self,receipt:s::MaterialRetired) { self.input.finish_retirement(receipt); }
    pub(crate) fn revoke_input_material(&mut self) { self.input.revoke_material(); }
    pub(crate) fn revoke_input_runner(&mut self,reason:p::Reason) { self.input.revoke_runner(reason); }
    pub(crate) fn input_runner_contexts(&self) -> impl Iterator<Item=&Arc<crate::asset_session::GitHubRunnerContext>> { self.input.runner.contexts() }
    fn input_revoke_consent(&mut self) {let before=self.input.snapshot();self.input.revoke_consent();self.input.finish(before);}
    pub(crate) fn input_active_registration(&self) -> Option<(&str,u32,&RegisteredRoot)> {
        self.input.active.as_ref().map(|v| (v.project_id.as_str(),v.generation,&v.root))
    }
    pub(crate) fn input_active_material(&self) -> Option<Arc<GitHubInputMaterial>> { self.input.active.as_ref().and_then(|v| v.material.clone()) }
    pub(crate) fn input_status(&mut self, qualified: bool, now: Instant, external: Reason) -> p::Status {
        let before = self.input.snapshot(); self.input.expire_consent(now);
        let reason = if self.unknown || self.exhausted || self.input.exhausted { p::Reason::CleanupUnknown }
            else if external != Reason::None { s::connection_reason(external) }
            else if !p::publisher_bound() { p::Reason::PublisherUnconfigured }
            else if !qualified { p::Reason::Unqualified }
            else if self.native_work_pending() || self.input.retirement_pending() { p::Reason::Busy }
            else if let Some(private) = &self.private {
                if let Some(reason) = private.retirement { s::connection_reason(reason) }
                else if now >= private.clock.end { p::Reason::Expired }
                else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { p::Reason::RateLimited }
                else if private.token.is_none() || private.account_pin.is_none() || private.repository_pin.is_none()
                    || self.status.account.state != FactState::Observed || self.status.repository.state != FactState::Observed
                    || !self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected) { p::Reason::NotConnected }
                else { p::Reason::None }
            } else { p::Reason::NotConnected };
        if reason != p::Reason::None && self.input.consent.is_some() { self.input.revoke_consent(); }
        self.input.view.available = reason == p::Reason::None; self.input.view.reason = reason;
        if let Some(private) = &self.private { self.input.view.session_id = Some(private.id.clone()); }
        else if self.input.view.operation.is_none() { self.input.view.session_id = None; }
        self.input.finish(before); self.input.snapshot()
    }
    fn input_context(&mut self, session: &str, revision: u32, generation: u32, binding: &str, now: Instant) -> Result<(String,p::PendingScope),BridgeError> {
        self.room().map_err(|e| s::refused(if e.code.ends_with("busy") { p::Reason::Busy } else { p::Reason::CleanupUnknown }))?;
        if self.input.view.revision != revision { return Err(s::refused(p::Reason::TargetChanged)); }
        if self.native_work_pending() || self.input.retirement_pending() { return Err(s::refused(p::Reason::Busy)); }
        if !self.input.view.available { return Err(s::refused(self.input.view.reason)); }
        let private = self.private.as_ref().filter(|v| v.id == session && v.generation == generation)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if now >= private.clock.end || private.retirement.is_some() || private.token.is_none() { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let repository = self.status.repository.value.as_ref().filter(|v| v.full_name.eq_ignore_ascii_case(&private.repository))
            .ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let scope = p::PendingScope { project_binding:binding.into(),repository:repository.full_name.clone(),
            account_id:private.account_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))?,
            repository_id:private.repository_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))? };
        if !scope.valid() { return Err(s::refused(p::Reason::InvalidInput)); }
        Ok((private.project_id.clone(),scope))
    }
    pub(crate) fn input_runner_check(&mut self,args:rp::CheckArgs,generation:u32,root:RegisteredRoot,binding:&str,
        context:Arc<crate::asset_session::GitHubRunnerContext>,supervisor:&Supervisor,now:Instant) -> Result<p::Status,BridgeError> {
        if !args.valid() || self.status.revision != args.expected_connection_revision {
            return Err(s::refused(p::Reason::TargetChanged));
        }
        let (project,scope)=self.input_context(&args.session_id,args.expected_revision,generation,binding,now)?;
        if context.generation()!=generation || context.root()!=&root {return Err(s::refused(p::Reason::ContextStale));}
        // An explicit new observation revokes the old one, including every
        // derived consent. A private material loan must finish its original
        // off-lock disposal before this independent read may be admitted.
        self.input.revoke_runner(p::Reason::RunnerUnverified);
        if self.input.retirement_pending() {return Err(s::refused(p::Reason::Busy));}
        if !supervisor.github_runner_prerequisite_profile_available() {return Err(s::refused(p::Reason::Unqualified));}
        if !self.input.view.fits_wire() {return Err(s::refused(p::Reason::ResponseLimit));}
        let private=self.private.as_ref().ok_or_else(||s::refused(p::Reason::NotConnected))?;
        let credential_end=private.clock.end;
        let ticket=supervisor.start_github_runner_prerequisite(&scope.repository,&scope.account_id,&scope.repository_id,
            private.token.as_deref().ok_or_else(||s::refused(p::Reason::Expired))?,credential_end)
            .map_err(|error|s::refused(match error.code.as_str() {
                "busy"=>p::Reason::Busy,"cleanup_unknown"=>p::Reason::CleanupUnknown,
                "cancelled"|"shutting_down"=>p::Reason::Cancelled,_=>p::Reason::RuntimeUnavailable }))?;
        let before=self.preflight.snapshot();self.preflight.revoke_consent();self.preflight.finish(before);
        let before=self.release.snapshot();self.release.revoke_consent();self.release.finish(before);
        let before=self.input.snapshot();
        self.input.view.session_id=Some(args.session_id.clone());self.input.view.runner=None;
        self.input.view.prepared=None;self.input.view.observation=None;
        self.input.view.available=false;self.input.view.reason=p::Reason::Busy;
        self.input.view.operation=Some(p::Operation {id:ticket.operation_id().into(),kind:p::OperationKind::RunnerCheck,
            phase:p::Phase::Running,reason:p::Reason::None});
        self.input.runner.active=Some(rs::Active {ticket,binding:rs::Binding {context,scope,session_id:args.session_id,project_id:project},
            credential_end,control_observed:false,revoked:None});
        self.input.finish(before);
        let before=self.status.clone();self.capability(now,Reason::None);self.finish(before);Ok(self.input.snapshot())
    }
    pub(super) fn reconcile_runner(&mut self,now:Instant,external:Reason) {
        let before=self.input.snapshot();self.input.expire_consent(now);
        let observed=self.input.runner.active.as_ref().filter(|active|!active.control_observed)
            .and_then(|active|active.ticket.observed_control());
        if let Some(observed)=observed {
            if let Some(active)=&mut self.input.runner.active {active.control_observed=true;}
            // The same original stdout reader captured this Instant at RESULT.
            // Observe authenticated limits before EOF/joins, exactly once. A
            // later status/settlement time must never renew a cooldown.
            if !self.apply_control(&observed.control,observed.observed_at) {self.retire_inner(Reason::ResponseInvalid,false);}
            else if observed.control.reason!=Reason::Expired && retires(observed.control.reason) {
                self.retire_inner(observed.control.reason,false);
            }
        }
        let state=self.input.runner.active.as_ref().map(|active|active.ticket.state());
        match state {
            Some(GitHubRunnerState::RetainedUnknown)=>self.unknown_inner(),
            Some(GitHubRunnerState::Settled {was_unknown})=>{
                let retiring=self.private.as_ref().is_none_or(|private|private.retirement.is_some());
                let revoked=self.input.runner.active.as_ref().is_some_and(|active|active.revoked.is_some());
                if external==Reason::None || retiring || revoked || was_unknown || self.unknown {
                    let result=self.input.runner.active.as_ref().and_then(|active|active.ticket.take_settled());
                    if let Some(result)=result {self.accept_runner(result,now.max(Instant::now()),external);}
                    else {self.unknown_inner();}
                }
            },
            Some(GitHubRunnerState::Pending)|None=>{},
        }
        if self.unknown {self.input.unknown();}
        else if external!=Reason::None {self.input.view.available=false;self.input.view.reason=s::connection_reason(external);}
        self.input.finish(before);
    }
    fn accept_runner(&mut self,result:GitHubRunnerResult,now:Instant,external:Reason) {
        // Only the consuming receipt of THIS exact active original ticket may
        // release it. RESULT bytes, control DATA and RetainedUnknown cannot.
        if !self.input.runner.active.as_ref().is_some_and(|active|result.belongs_to(&active.ticket)) {
            self.unknown_inner();return; // Retain the unrelated original active owner.
        }
        let Some(active)=self.input.runner.active.take() else {self.unknown_inner();return;};
        let observed=active.ticket.observed_control();
        let mut reason=result.outcome.as_ref().map_or_else(s::outcome_reason,|reply|reply.reason);
        let mut unknown=result.was_unknown || self.unknown || reason==p::Reason::CleanupUnknown
            || result.outcome.as_ref().is_ok_and(|reply|reply.network_cleanup==p::Settlement::Unknown);
        if self.private.as_ref().is_some_and(|private|private.retirement.is_none() && now>=private.clock.end) {
            self.retire_inner(Reason::Expired,false);
        }
        let retirement=self.private.as_ref().and_then(|private|private.retirement);
        if let Some(retired)=retirement {reason=s::connection_reason(retired);}
        else if let Some(revoked)=active.revoked {reason=revoked;}
        else if reason==p::Reason::Expired {reason=p::Reason::NetworkUnavailable;} // Work timeout is not credential expiry.
        if !unknown && reason==p::Reason::None {
            let publication=(|| -> Result<(Arc<rs::Evidence>,rp::Summary),BridgeError> {
                if external!=Reason::None {return Err(s::refused(s::connection_reason(external)));}
                let private=self.private.as_ref().filter(|private|private.retirement.is_none() && private.token.is_some()
                    && private.id==active.binding.session_id && private.project_id==active.binding.project_id
                    && private.generation==active.binding.context.generation() && now<private.clock.end
                    && private.account_pin.as_ref()==Some(&active.binding.scope.account_id)
                    && private.repository_pin.as_ref()==Some(&active.binding.scope.repository_id)
                    && private.repository.eq_ignore_ascii_case(&active.binding.scope.repository))
                    .ok_or_else(||s::refused(p::Reason::TargetChanged))?;
                if self.cooldown_blocked || self.cooldown.is_some_and(|end|now<end) {return Err(s::refused(p::Reason::RateLimited));}
                if self.status.account.state!=FactState::Observed || self.status.repository.state!=FactState::Observed
                    || !self.status.session.as_ref().is_some_and(|session|session.state==SessionState::Connected) {
                    return Err(s::refused(p::Reason::NotConnected));
                }
                let observed=observed.as_ref().ok_or_else(BridgeError::protocol)?;
                let evidence=rs::Evidence::from_original(result,&active,observed,now,private.clock.end)?;
                let expires=private.clock.display_end(evidence.end()).ok_or_else(BridgeError::protocol)?;
                let summary=evidence.summary(expires);
                if summary.checked_at.as_ref()>=summary.expires_at.as_ref() {return Err(s::refused(p::Reason::Expired));}
                Ok((evidence,summary))
            })();
            match publication {
                Ok((evidence,summary))=>{self.input.runner.observation=Some(evidence);self.input.view.runner=Some(summary);},
                Err(error)=>reason=s::outcome_reason(&error),
            }
        }
        unknown |= reason==p::Reason::CleanupUnknown;
        if unknown {reason=p::Reason::CleanupUnknown;}
        if reason!=p::Reason::None {self.input.runner.observation=None;self.input.view.runner=Some(rp::Summary::refused(reason));}
        if let Some(operation)=&mut self.input.view.operation {
            if operation.id!=active.ticket.operation_id() || operation.kind!=p::OperationKind::RunnerCheck {
                self.unknown_inner();return;
            }
            operation.phase=if unknown {p::Phase::CleanupUnknown}else{p::Phase::Settled};operation.reason=reason;
        } else {self.unknown_inner();return;}
        if unknown {self.unknown_inner();}
        else if matches!(reason,p::Reason::Unauthorized|p::Reason::TargetChanged|p::Reason::ResponseInvalid|p::Reason::Cancelled) {
            self.retire_inner(match reason {p::Reason::Unauthorized=>Reason::Unauthorized,p::Reason::TargetChanged=>Reason::TargetChanged,
                p::Reason::ResponseInvalid=>Reason::ResponseInvalid,_=>Reason::Cancelled},false);
        }
        if retirement.is_some() || unknown {self.complete_retirement();}
    }
    fn input_start(&mut self, request: p::Request, material: Option<Arc<GitHubInputMaterial>>, consent_end: Option<Instant>, runner:Option<rs::BoundRunner>,
        root: RegisteredRoot, gate: GitHubInputGoGate, supervisor: &Supervisor, now: Instant) -> Result<p::Status,BridgeError> {
        if !supervisor.github_input_group_profile_available() || !p::publisher_bound() { return Err(s::refused(p::Reason::Unqualified)); }
        if !request.valid() || self.native_work_pending() || self.input.retirement_pending() { return Err(s::refused(p::Reason::Busy)); }
        if !self.input.view.fits_wire() { return Err(s::refused(p::Reason::ResponseLimit)); }
        let private = self.private.as_ref().ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let (session_id,project_id,generation) = (private.id.clone(),private.project_id.clone(),private.generation);
        let ticket = supervisor.start_github_input_group(request.clone(),gate).map_err(|e|
            s::refused(match e.code.as_str() { "busy" => p::Reason::Busy,"cleanup_unknown" => p::Reason::CleanupUnknown,
                "cancelled" | "shutting_down" => p::Reason::Cancelled,_ => p::Reason::RuntimeUnavailable }))?;
        let before = self.preflight.snapshot(); self.preflight.revoke_consent(); self.preflight.finish(before);
        let before = self.release.snapshot(); self.release.revoke_consent(); self.release.finish(before);
        self.input.start(s::Active { ticket,request,session_id,project_id,generation,root,material,material_revoked:false,
            admitted_at:now,consent_end,runner,control_observed:false,reply_control_observed:false });
        let before = self.status.clone(); self.capability(now,Reason::None); self.finish(before); Ok(self.input.snapshot())
    }
    pub(crate) fn input_prepare(&mut self,args:p::PrepareArgs,generation:u32,root:RegisteredRoot,binding:&str,marker:String,
        material:Arc<GitHubInputMaterial>,gate:GitHubInputGoGate,supervisor:&Supervisor,now:Instant) -> Result<p::Status,BridgeError> {
        if self.status.revision != args.expected_connection_revision { return Err(s::refused(p::Reason::TargetChanged)); }
        let (_,scope) = self.input_context(&args.session_id,args.expected_revision,generation,binding,now)?;
        if self.input.records.len() >= p::RECORD_LIMIT { return Err(s::refused(p::Reason::ResponseLimit)); }
        let target = p::Target { project_binding:scope.project_binding,repository:scope.repository,account_id:scope.account_id,
            repository_id:scope.repository_id,branch:args.branch,tooling_repository:p::TOOLING_REPOSITORY.into(),
            tooling_sha:p::TOOLING_SHA.ok_or_else(|| s::refused(p::Reason::PublisherUnconfigured))?.into(),
            scope:material.scope(),kind:material.assignment().kind,marker,native_config_sha256:material.config_digest().into() };
        if !target.publisher_bound() || material.assignment() != &args.assignment { return Err(s::refused(p::Reason::AssignmentUnavailable)); }
        if self.input.consent.is_some() { self.input_revoke_consent(); return Err(s::refused(p::Reason::Busy)); }
        self.input_start(p::Request { action:Some(p::Action {kind:p::Kind::Prepare,target,prepared:None}),pending_scope:None,home:None },
            Some(material),None,None,root,gate,supervisor,now)
    }
    fn input_runner_evidence(&self,prepared:&p::Prepared,root:&RegisteredRoot,now:Instant) -> Result<&Arc<rs::Evidence>,BridgeError> {
        let private=self.private.as_ref().filter(|v|v.retirement.is_none() && v.token.is_some() && now<v.clock.end)
            .ok_or_else(||s::refused(p::Reason::Expired))?;
        let scope=p::PendingScope {project_binding:prepared.target.project_binding.clone(),repository:prepared.target.repository.clone(),
            account_id:prepared.target.account_id.clone(),repository_id:prepared.target.repository_id.clone()};
        if private.account_pin.as_ref()!=Some(&scope.account_id) || private.repository_pin.as_ref()!=Some(&scope.repository_id)
            || !private.repository.eq_ignore_ascii_case(&scope.repository) {return Err(s::refused(p::Reason::TargetChanged));}
        self.input.runner.observation.as_ref().filter(|e| e.current(&private.id,&private.project_id,&scope,private.generation,root,now))
            .ok_or_else(||s::refused(p::Reason::RunnerUnverified))
    }
    fn input_mutation_prerequisite(&self,prepared:&p::Prepared,material:&GitHubInputMaterial,bound:Option<&rs::BoundRunner>,
        root:&RegisteredRoot,now:Instant) -> Result<(),BridgeError> {
        let evidence=self.input_runner_evidence(prepared,root,now)?;
        if !prepared.production_reviewed() {return Err(s::refused(p::Reason::EnvironmentUnready));}
        if !bound.is_some_and(|b|b.current(evidence,prepared,material,now)) {return Err(s::refused(p::Reason::RunnerUnverified));}
        Ok(())
    }
    pub(crate) fn input_apply(&mut self,args:p::ApplyArgs,generation:u32,root:RegisteredRoot,binding:&str,home:String,
        gate:GitHubInputGoGate,supervisor:&Supervisor,now:Instant) -> Result<p::Status,BridgeError> {
        let (project,scope) = self.input_context(&args.session_id,args.expected_revision,generation,binding,now)?;
        let consent = self.input.consent.as_ref().filter(|v| !v.revoked && v.session_id == args.session_id && v.project_id == project
            && v.generation == generation && v.root == root && now < v.end && v.prepared.target.marker == args.consent_id
            && scope.matches(&v.prepared.target) && v.prepared.publisher_bound() && args.confirm_upsert_whole_group)
            .ok_or_else(|| s::refused(p::Reason::ConsentExpired))?;
        self.input_mutation_prerequisite(&consent.prepared,&consent.material,consent.runner.as_ref(),&consent.root,now)?;
        let record = p::PrivateRecord { prepared:consent.prepared.clone(),write:p::RemoteWrite::NotAttempted,intent_sha256:consent.prepared.intent_digest()? };
        // Prepare reserved this future row. All fallible history allocation and
        // shape checks happen before the original ticket/one-use mutation gate.
        self.input.retain_record(record,p::Completion {journal:p::Settlement::Pending,cleanup:p::Settlement::Pending,finality:p::Finality::Pending},p::Reason::None)?;
        let before = self.input.snapshot();
        let mut consent = self.input.consent.take().ok_or_else(|| s::refused(p::Reason::ConsentExpired))?;
        self.input.view.prepared = None; self.input.finish(before);
        let request = p::Request { action:Some(p::Action {kind:p::Kind::Apply,target:consent.prepared.target.clone(),prepared:Some(consent.prepared.clone())}),
            pending_scope:None,home:Some(home) };
        let result = self.input_start(request,Some(consent.material.clone()),Some(consent.end),consent.runner.take(),root,gate,supervisor,now);
        if let Err(error) = &result {
            let before=self.input.snapshot();
            if let Some(row)=self.input.view.records.iter_mut().find(|r| r.original_operation_id==consent.prepared.target.marker) {
                row.reason=s::outcome_reason(error); row.completion=p::Completion {journal:p::Settlement::NotRun,cleanup:p::Settlement::Confirmed,finality:p::Finality::Settled};
            }
            self.input.consent = Some(consent); self.input.revoke_consent();
            self.input.defer_material_finality(None,Some(&args.consent_id));self.input.finish(before);
        }
        result
    }
    pub(crate) fn input_observe(&mut self,args:p::ReconcileArgs,generation:u32,root:RegisteredRoot,binding:&str,home:String,
        gate:GitHubInputGoGate,supervisor:&Supervisor,now:Instant) -> Result<p::Status,BridgeError> {
        let (_,scope) = self.input_context(&args.session_id,args.expected_revision,generation,binding,now)?;
        let record = self.input.record(&args.original_operation_id).filter(|r| scope.matches(&r.prepared.target) && r.prepared.publisher_bound())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?.clone();
        if self.input.consent.is_some() { self.input_revoke_consent(); return Err(s::refused(p::Reason::Busy)); }
        self.input_start(p::Request {action:Some(p::Action {kind:p::Kind::Reconcile,target:record.prepared.target.clone(),prepared:Some(record.prepared)}),
            pending_scope:None,home:Some(home)},None,None,None,root,gate,supervisor,now)
    }
    pub(crate) fn input_pending(&mut self,args:p::ControlArgs,generation:u32,root:RegisteredRoot,binding:&str,home:String,
        gate:GitHubInputGoGate,supervisor:&Supervisor,now:Instant) -> Result<p::Status,BridgeError> {
        let (_,scope) = self.input_context(&args.session_id,args.expected_revision,generation,binding,now)?;
        if self.input.consent.is_some() { self.input_revoke_consent(); return Err(s::refused(p::Reason::Busy)); }
        self.input_start(p::Request {action:None,pending_scope:Some(scope),home:Some(home)},None,None,None,root,gate,supervisor,now)
    }
    pub(crate) fn input_cancel(&mut self,id:&str) -> Result<p::Status,BridgeError> { self.input.cancel(id)?; Ok(self.input.snapshot()) }
    fn input_claim_context(&self,id:&str,request:&p::Request,now:Instant) -> Result<(&PrivateSession,&s::Active),BridgeError> {
        let active = self.input.active.as_ref().filter(|v| v.ticket.operation_id() == id && &v.request == request && !v.material_revoked)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        let private = self.private.as_ref().filter(|v| v.id == active.session_id && v.project_id == active.project_id
            && v.generation == active.generation && v.retirement.is_none() && v.ticket.is_none() && v.device.is_none())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if self.unknown || self.exhausted || self.input.exhausted { return Err(s::refused(p::Reason::CleanupUnknown)); }
        if self.preflight.native_work_pending() || self.release.native_work_pending() || self.input.retirement_pending() { return Err(s::refused(p::Reason::Busy)); }
        if now >= private.clock.end || private.token.is_none() { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let (account,repository,coordinate) = request.action.as_ref().map(|a| (&a.target.account_id,&a.target.repository_id,&a.target.repository))
            .or_else(|| request.pending_scope.as_ref().map(|s| (&s.account_id,&s.repository_id,&s.repository))).ok_or_else(BridgeError::protocol)?;
        if private.account_pin.as_ref() != Some(account) || private.repository_pin.as_ref() != Some(repository)
            || !coordinate.eq_ignore_ascii_case(&private.repository) { return Err(s::refused(p::Reason::TargetChanged)); }
        if let Some(action) = &request.action { if !action.target.publisher_bound() { return Err(s::refused(p::Reason::CallerIncompatible)); } }
        Ok((private,active))
    }
    pub(crate) fn input_read(&self,id:&str,digest:&str,request:&p::Request,now:Instant,claim:impl FnOnce()->bool) -> Result<p::PrivateFrame,BridgeError> {
        let (private,active) = self.input_claim_context(id,request,now)?;
        if active.ticket.read_claimed() { return Err(s::refused(p::Reason::Cancelled)); }
        let frame = p::encode_read(id,digest,if request.kind() == p::Kind::Pending {None} else {private.token.as_deref()},request.kind())?;
        if !claim() { return Err(s::refused(p::Reason::Cancelled)); } Ok(frame)
    }
    pub(crate) fn input_go(&self,id:&str,request:&p::Request,rechecked:&p::Rechecked,now:Instant,claim:impl FnOnce()->bool) -> Result<(),BridgeError> {
        let (_,active) = self.input_claim_context(id,request,now)?;
        let original = request.action.as_ref().filter(|a| a.kind == p::Kind::Apply).and_then(|a| a.prepared.as_ref()).ok_or_else(BridgeError::protocol)?;
        let material = active.material.as_ref().ok_or_else(|| s::refused(p::Reason::AssignmentUnavailable))?;
        if !active.ticket.read_claimed() || active.ticket.go_claimed() || !active.consent_end.is_some_and(|end| now < end)
            || !original.same_original(&rechecked.snapshot) || material.config_digest() != original.target.native_config_sha256
            || material.assignment().kind != original.target.kind { return Err(s::refused(p::Reason::ConsentExpired)); }
        self.input_mutation_prerequisite(original,material,active.runner.as_ref(),&active.root,now)?;
        // Rechecked was authenticated/hashed before this gate; all private GO
        // serialization and sealing already finished. Only one atomic claim.
        if !claim() { return Err(s::refused(p::Reason::Cancelled)); } Ok(())
    }
    pub(super) fn reconcile_input(&mut self,now:Instant,external:Reason) {
        let before = self.input.snapshot(); self.input.expire_consent(now);
        // Observe the independent correlated mailbox even if RESULT/native
        // retirement later fails. Its original observed_at fixes cooldown.
        let remote = self.input.active.as_ref().filter(|a| !a.control_observed).and_then(|a| a.ticket.remote());
        if let Some(remote) = remote {
            let marker = self.input.active.as_ref().and_then(|a| a.request.action.as_ref()).map(|a| a.target.marker.clone());
            if let Some(marker) = marker { if self.input.observe_remote(&marker,&remote.fact.write).is_err() { self.unknown_inner(); } }
            let consume = self.input.active.as_ref().is_some_and(|a| !a.control_observed);
            if consume {
                if let Some(active) = &mut self.input.active { active.control_observed = true; }
                if !self.apply_control(&remote.fact.control,remote.observed_at) { self.retire_inner(Reason::ResponseInvalid,false); }
                else if retires(remote.fact.control.reason) { self.retire_inner(remote.fact.control.reason,false); }
            }
        }
        // RESULT may carry authenticated expiry/cooldown DATA even when its
        // original process/EOF/cleanup has not settled. Consume it once now,
        // not only after settlement, and never move an earlier PUT clock to the
        // later RESULT/journal/observation time.
        let reply = self.input.active.as_ref().filter(|a| !a.reply_control_observed).and_then(|a| a.ticket.observed_reply());
        if let Some(reply) = reply {
            let at=self.input.active.as_ref().and_then(|a| a.ticket.remote()).map_or(reply.observed_at,|v| v.observed_at);
            if let Some(active)=&mut self.input.active {active.reply_control_observed=true;}
            if let Some(outcome)=&reply.reply.result {
                if !self.apply_control(&outcome.control,at) {self.retire_inner(Reason::ResponseInvalid,false);}
                else if retires(outcome.control.reason) {self.retire_inner(outcome.control.reason,false);}
            }
        }
        if let Some(active) = &self.input.active {
            if active.request.kind() == p::Kind::Apply && active.ticket.go_claimed() {
                if let Some(marker) = active.request.action.as_ref().map(|a| &a.target.marker) {
                    if let Some(row) = self.input.view.records.iter_mut().find(|r| &r.original_operation_id == marker) {
                        if row.write == p::RemoteWrite::NotAttempted { row.write = p::RemoteWrite::AttemptedOutcomeUnknown; }
                    }
                }
            }
        }
        match self.input.receipt() {
            Some(GitHubInputGroupReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(GitHubInputGroupReceipt::Settled {outcome,settled_at,was_unknown}) => self.accept_input(outcome,settled_at,was_unknown,now,external),
            None | Some(GitHubInputGroupReceipt::Pending) => {},
        }
        if self.unknown { self.input.unknown(); }
        else if external != Reason::None { self.input.view.available=false; self.input.view.reason=s::connection_reason(external); }
        self.input.finish(before);
    }
    fn accept_input(&mut self,result:Result<p::Reply,BridgeError>,settled_at:Instant,was_unknown:bool,now:Instant,external:Reason) {
        let Some(active) = self.input.active.as_ref() else { self.unknown_inner(); return; };
        let kind=active.request.kind(); let go=active.ticket.go_claimed(); let read=active.ticket.read_claimed();
        let observed_reply=active.ticket.observed_reply();
        let reply=observed_reply.as_ref().map(|v| v.reply.clone()).or_else(|| result.as_ref().ok().cloned());
        let network=reply.as_ref().and_then(|v|v.result.as_ref()).map(|v|v.network_cleanup);
        let control_observed=active.reply_control_observed;
        let mut reason=result.as_ref().map_or_else(s::outcome_reason,|r| r.result.as_ref().map_or(p::Reason::None,|v| v.reason));
        if !control_observed {
            if let Some(outcome)=reply.as_ref().and_then(|v|v.result.as_ref()) {
                let observed=self.input.active.as_ref().and_then(|a|a.ticket.remote()).map(|v|v.observed_at)
                    .unwrap_or_else(||observed_reply.as_ref().map_or(settled_at,|v|v.observed_at));
                if !self.apply_control(&outcome.control,observed) {reason=p::Reason::ResponseInvalid;self.retire_inner(Reason::ResponseInvalid,false);}
                else if retires(outcome.control.reason) {self.retire_inner(outcome.control.reason,false);}
            }
        }
        if self.private.as_ref().is_some_and(|v| now>=v.clock.end && v.retirement.is_none()) { self.retire_inner(Reason::Expired,false); }
        let unknown=was_unknown || self.unknown || reason==p::Reason::CleanupUnknown;
        let retirement=self.private.as_ref().and_then(|v| v.retirement);
        if let Some(retirement)=retirement { reason=s::connection_reason(retirement); }
        if reason==p::Reason::Expired && retirement.is_none() { reason=p::Reason::NetworkUnavailable; }
        // Do not publish a new consent during an accepted stop/quit/context loss.
        let mut consent=None;
        if result.is_ok() && !unknown && retirement.is_none() && external==Reason::None && reason==p::Reason::None && kind==p::Kind::Prepare {
            let prepared=reply.as_ref().and_then(|r| r.result.as_ref()).and_then(|o| o.prepared.as_ref());
            let active=self.input.active.as_ref();
            let publication=(|| -> Result<s::Consent,BridgeError> {
                let (prepared,active)=prepared.zip(active).ok_or_else(BridgeError::protocol)?;
                let material=active.material.as_ref().filter(|_| !active.material_revoked).ok_or_else(|| s::refused(p::Reason::AssignmentUnavailable))?;
                if !prepared.publisher_bound() || !prepared.public_record_fits() { return Err(BridgeError::protocol()); }
                let runner=self.input_runner_evidence(prepared,&active.root,now)?.bind(prepared,material,now)?;
                let private=self.private.as_ref().ok_or_else(BridgeError::protocol)?;
                let end=active.admitted_at.checked_add(Duration::from_secs(120)).ok_or_else(BridgeError::protocol)?.min(private.clock.end).min(runner.end());
                if now>=end { return Err(s::refused(p::Reason::ConsentExpired)); }
                Ok(s::Consent {prepared:prepared.clone(),end,session_id:active.session_id.clone(),project_id:active.project_id.clone(),
                    generation:active.generation,root:active.root.clone(),material:material.clone(),revoked:false,runner:Some(runner)})
            })();
            match publication { Ok(value)=>consent=Some(value),Err(error)=>reason=s::outcome_reason(&error) }
        }
        if let Some(mut consent)=consent {
            let display=self.private.as_ref().and_then(|v| v.clock.display_end(consent.end));
            if let Some(display)=display.filter(|v| consent.prepared.observed_at < *v) {
                let public=p::PublicPrepared {consent_id:consent.prepared.target.marker.clone(),target:consent.prepared.public_target(),
                    assignment:consent.material.assignment().clone(),fields:consent.material.fields(),metadata:consent.prepared.metadata.clone(),
                    destination:p::Destination {state:"fits",plaintext_limit_bytes:p::ENVELOPE_LIMIT},effect:"upsert-one-complete-group",
                    observed_at:consent.prepared.observed_at.clone(),consent_expires_at:display};
                self.input.view.prepared=Some(public); self.input.consent=Some(consent);
            } else { consent.revoked=true; self.input.consent=Some(consent); self.input.revoke_consent(); reason=p::Reason::ConsentExpired; }
        }
        // Only an actual Settled receipt reaches here. Transfer the active
        // material to the fixed off-lock book before dropping its original Arc.
        let Some(active)=self.input.take_finished() else { self.unknown_inner(); return; };
        if let Some(reply)=reply {
            if let Some(records)=reply.pending {
                for record in records {
                    let old=self.input.view.records.iter().find(|r|r.original_operation_id==record.prepared.target.marker);
                    let completion=old.map(|r|r.completion.clone()).unwrap_or(p::Completion {
                        journal:p::Settlement::Confirmed,cleanup:p::Settlement::Unknown,finality:p::Finality::Unknown});
                    let record_reason=old.map_or(p::Reason::CleanupUnknown,|r|r.reason);
                    if self.input.retain_record(record,completion,record_reason).is_err() { reason=p::Reason::ResponseInvalid; break; }
                }
            }
            if let Some(outcome)=reply.result {
                if let Some(record)=outcome.record {
                    let cleanup=completion_cleanup(Some(outcome.network_cleanup),read,unknown);
                    let completion=p::Completion {journal:outcome.journal,cleanup,finality:if cleanup==p::Settlement::Confirmed {p::Finality::Settled} else {p::Finality::Unknown}};
                    // Reconciliation cannot settle the old writer's native
                    // cleanup. Preserve its existing completion/acknowledgment.
                    let completion=if kind==p::Kind::Reconcile {
                        self.input.view.records.iter().find(|r| r.original_operation_id==record.prepared.target.marker).map(|r| r.completion.clone())
                            .unwrap_or(p::Completion {journal:outcome.journal,cleanup:p::Settlement::Unknown,finality:p::Finality::Unknown})
                    } else {completion};
                    if self.input.retain_record(record,completion,reason).is_err() { reason=p::Reason::ResponseInvalid; }
                }
                if !unknown && result.is_ok() && reason==p::Reason::None { self.input.view.observation=outcome.observation; }
            }
        }
        if kind==p::Kind::Apply {
            if let Some(marker)=active.request.action.as_ref().map(|a| &a.target.marker) {
                if let Some(row)=self.input.view.records.iter_mut().find(|r| &r.original_operation_id==marker) {
                    if go && row.write==p::RemoteWrite::NotAttempted && result.is_err() { row.write=p::RemoteWrite::AttemptedOutcomeUnknown; }
                    if result.is_err() { row.reason=reason; row.completion.journal=if row.completion.journal==p::Settlement::Confirmed {p::Settlement::Confirmed} else {p::Settlement::Unknown}; }
                    if unknown { row.reason=p::Reason::CleanupUnknown; row.completion.cleanup=p::Settlement::Unknown; row.completion.finality=p::Finality::Unknown; }
                    else if row.completion.cleanup==p::Settlement::Pending {
                        row.completion.cleanup=completion_cleanup(network,read,false);
                        row.completion.finality=if row.completion.cleanup==p::Settlement::Confirmed {p::Finality::Settled} else {p::Finality::Unknown};
                    }
                }
            }
        }
        if let Some(op)=&mut self.input.view.operation {op.phase=if unknown {p::Phase::CleanupUnknown} else {p::Phase::Settled};op.reason=if unknown {p::Reason::CleanupUnknown} else {reason};}
        if unknown {self.unknown_inner();}
        else if matches!(reason,p::Reason::Unauthorized|p::Reason::TargetChanged|p::Reason::ResponseInvalid|p::Reason::Cancelled) {
            self.retire_inner(match reason {p::Reason::Unauthorized=>Reason::Unauthorized,p::Reason::TargetChanged=>Reason::TargetChanged,
                p::Reason::ResponseInvalid=>Reason::ResponseInvalid,_=>Reason::Cancelled},false);
        }
        if retirement.is_some() {self.complete_retirement();}
        let marker=if kind==p::Kind::Apply {active.request.action.as_ref().map(|a|a.target.marker.as_str())} else {None};
        self.input.defer_material_finality(Some(active.ticket.operation_id()),marker);
    }
}

#[cfg(test)]
#[path = "github_connection_input_group_tests.rs"]
mod tests;
