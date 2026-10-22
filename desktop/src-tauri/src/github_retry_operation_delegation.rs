//! The original actions_retry State owns the captured input, native ticket and
//! private Prepared. Public result/marker data cannot create any of these.
use super::*;
use action_delegation::operation::{self as d, Input, Permission, Records, Producer, producer_ready, hash};
use crate::{service_github_action_protocol as wire, service_github_action_requests as rows};
pub(super) const RETURN_BACKING: usize = 16 * 1024;
fn no() -> BridgeError { refused(p::Reason::TargetChanged) }
pub(super) fn request_kind(kind: wire::Kind, native: p::Kind) -> bool {
    matches!((kind,native), (wire::Kind::FailedJobsPrepare,p::Kind::Prepare)
        | (wire::Kind::FailedJobsPending,p::Kind::Pending) | (wire::Kind::FailedJobsReconcile,p::Kind::Reconcile))
}
fn marker(t: &p::Target) -> Option<&str> { t.marker() }
fn scope_matches(t: &p::Target, c: &d::Capture) -> bool { t.scope.project_binding==c.binding && t.scope.account_id==c.account && Some(&t.scope.repository_id)==c.repository.as_ref() && t.scope.repository.eq_ignore_ascii_case(&c.coordinate) }
impl State {
    pub(super) fn operation_heap(&self) -> Option<usize> {
        (2 * std::mem::size_of::<usize>()).checked_add(self.agent_permission.as_ref().map_or(Some(0),Permission::heap)?)?
            .checked_add(self.agent_records.as_ref().map_or(Some(0),Records::heap)?)?
            .checked_add(self.consent.as_ref().and_then(|c|c.producer.as_ref()).map_or(0,Producer::heap))
    }
}
impl Input {
    pub(crate) fn actions_retry_command(&self) -> Result<p::Command,BridgeError> {
        Ok(match self {
            Self::FailedJobsPrepare(v) => p::Command::Prepare(v.as_ref().clone()),
            Self::FailedJobsPending(v) => p::Command::Pending(v.as_ref().clone()),
            Self::FailedJobsReconcile(v) => p::Command::Reconcile(v.as_ref().clone()),
            _ => return Err(no()),
        })
    }
    fn matches_actions_retry(&self, command:&p::Command) -> bool {
        match (self,command) {
            (Self::FailedJobsPrepare(a),p::Command::Prepare(b)) => a.as_ref()==b,
            (Self::FailedJobsPending(a),p::Command::Pending(b)) => a.as_ref()==b,
            (Self::FailedJobsReconcile(a),p::Command::Reconcile(b)) => a.as_ref()==b,
            _ => false,
        }
    }
}
impl ConnectionState {
    pub(crate) fn actions_retry_operation_permission_retained(&self)->bool { self.actions_retry.agent_permission.is_some() }
    pub(crate) fn actions_retry_operation_review(&self, input:Input, generation:u32, root:&RegisteredRoot,
        binding:&str, edit:&SavedEditGuard<'_>, now:Instant, consumer:Option<&Arc<rows::Entry>>)
        -> Result<action_delegation::Review,BridgeError> {
        let st=&self.actions_retry;
        if st.exhausted || !st.view.available || st.view.reason!=p::Reason::None || st.view.revision!=input.revision()
            || st.consent.is_some() || st.agent_permission.is_some() && consumer.is_none() { return Err(no()); }
        if consumer.is_some_and(|e| st.agent_permission.as_ref().is_none_or(|p| p.claimed
            || p.scope.upgrade().is_none_or(|s| !Arc::ptr_eq(&s,e.scope())))) { return Err(no()); }
        let capture=self.operation_capture(input,generation,root,binding,now)?;
        let input=&capture.input;
        let mut end=now.checked_add(Duration::from_millis(wire::INTENT_MS)).ok_or_else(no)?.min(capture.credential_end);
        let (identity,data)=match input {
            Input::FailedJobsPrepare(_) | Input::FailedJobsPending(_) => {
                let r=wire::dispatch::RequestReference {session_id:input.session().into(),expected_revision:input.revision(),request_sha256:hash(input)?};
                (st.agent_identity.clone(),if matches!(input,Input::FailedJobsPrepare(_)) {wire::Review::FailedJobsPrepare(r)} else {wire::Review::FailedJobsPending(r)})
            }
            Input::FailedJobsReconcile(a) => {
                let row=st.view.pending.iter().find(|r|marker(&r.prepared.target)==Some(a.marker.as_str())).ok_or_else(no)?;
                let original=st.agent_records.as_ref().ok_or_else(no)?;
                if !original.current(&st.view.pending,st.view.operation.as_ref().map(|o|o.id.as_str()),input.session(),generation,root,edit,now)
                    || !scope_matches(&row.prepared.target,&capture) { return Err(no()); }
                end=end.min(original.end);
                (original.identity.clone(),wire::Review::FailedJobsReconcile(wire::PendingReference {
                    session_id:input.session().into(),expected_revision:input.revision(),marker:a.marker.clone(),record_sha256:hash(row)?,
                }))
            }
            _=>return Err(no()),
        };
        if !data.valid() || !data.retained_fits() { return Err(no()); }
        Ok(action_delegation::Review { identity,stamp:edit.stamp()?,end,data,activity:None,dispatch:None,enrollment:None,operation:Some(capture) })
    }
    pub(crate) fn actions_retry_operation_allow(&mut self, review:action_delegation::Review, scope:&Arc<rows::NativeScope>)->Result<(),BridgeError> {
        if self.native_work_pending() || self.actions_retry.agent_permission.is_some() || self.actions_retry.consent.is_some()
            || scope.review!=review.data || !Arc::ptr_eq(&scope.identity,&review.identity) || scope.current(false).is_err() { return Err(no()); }
        let capture=review.operation.ok_or_else(no)?;
        let same=match &capture.input {
            Input::FailedJobsPrepare(_) | Input::FailedJobsPending(_) => Arc::ptr_eq(&self.actions_retry.agent_identity,&review.identity),
            Input::FailedJobsReconcile(_) => self.actions_retry.agent_records.as_ref().is_some_and(|r|Arc::ptr_eq(&r.identity,&review.identity)),
            _=>false,
        };
        if !same { return Err(no()); }
        self.actions_retry.agent_permission=Some(Permission {scope:Arc::downgrade(scope),capture,stamp:review.stamp,claimed:false});
        Ok(())
    }
    pub(crate) fn actions_retry_operation_input(&self,entry:&Arc<rows::Entry>)->Result<Input,BridgeError> {
        let p=self.actions_retry.agent_permission.as_ref().ok_or_else(no)?;
        if p.claimed || p.scope.upgrade().is_none_or(|s|!Arc::ptr_eq(&s,entry.scope())) { return Err(no()); }
        Ok(p.capture.input.clone())
    }
    /// This check is before expire/status/registry/context_changed in the OUTER
    /// original command path. A losing GUI/foreign request cannot retire the
    /// linked original as a side effect of failing its later input checks.
    pub(crate) fn actions_retry_operation_origin(&self,command:&p::Command,entry:Option<&Arc<rows::Entry>>)->Result<(),BridgeError> {
        let st=&self.actions_retry;
        if let p::Command::Cancel(a)=command {
            return if entry.is_none() && st.active.as_ref().is_some_and(|o|o.ticket.operation_id()==a.operation_id) {Ok(())} else {Err(no())};
        }
        if let Some(e)=entry {
            if e.scope().review.kind().operation_family() {
                let p=st.agent_permission.as_ref().ok_or_else(no)?;
                if p.claimed || p.scope.upgrade().is_none_or(|s|!Arc::ptr_eq(&s,e.scope()))
                    || !p.capture.input.matches_actions_retry(command) || e.current(false).is_err() { return Err(no()); }
                return Ok(());
            }
            if !matches!(command,p::Command::Start(_)) || st.agent_permission.is_some()
                || !action_delegation::origin(&st.consent.as_ref().and_then(|c|c.agent.clone()),Some(e))
                || st.consent.as_ref().is_none_or(|c|!producer_ready(&c.producer)) { return Err(no()); }
            return Ok(());
        }
        if st.agent_permission.is_some() || st.active.as_ref().is_some_and(|a|a.agent.is_some())
            || st.consent.as_ref().is_some_and(|c|c.agent.is_some() || !producer_ready(&c.producer)) { return Err(no()); }
        Ok(())
    }
    pub(crate) fn actions_retry_operation_entry(&mut self,command:&p::Command,entry:Option<&Arc<rows::Entry>>,
        generation:u32,root:&RegisteredRoot,binding:&str,edit:&SavedEditGuard<'_>,now:Instant)->Result<(),BridgeError> {
        let Some(entry)=entry.filter(|e|e.scope().review.kind().operation_family()) else {return Ok(())};
        entry.current(false).map_err(crate::asset_session::application_service::public_error)?;
        let input=self.actions_retry_operation_input(entry)?;
        if !input.matches_actions_retry(command) {return Err(no());}
        let review=self.actions_retry_operation_review(input,generation,root,binding,edit,now,Some(entry))?;
        let p=self.actions_retry.agent_permission.as_mut().ok_or_else(no)?;
        if review.data!=entry.scope().review || !Arc::ptr_eq(&review.identity,&entry.scope().identity)
            || review.operation.as_ref().is_none_or(|c|!c.same(&p.capture)) || !edit.matches(&p.stamp) {return Err(no());}
        p.claimed=true; // before original admission; failures never reopen it
        Ok(())
    }
    pub(crate) fn actions_retry_operation_revoke(&mut self,scope:&Arc<rows::NativeScope>) {
        let st=&mut self.actions_retry;
        if st.agent_permission.as_ref().and_then(|p|p.scope.upgrade()).is_none_or(|s|!Arc::ptr_eq(&s,scope)) {return;}
        let before=st.view.clone();
        // Completed producer permission ONLY: preserve the actual Prepared and
        // pending witness. Never use current phase/project/kind as its identity.
        let unreturned_producer = st.consent.as_ref().is_some_and(|c| c.producer.as_ref().is_some_and(|p|p.belongs_to(scope)) && !producer_ready(&c.producer))
            || st.agent_records.as_ref().is_some_and(|r|r.producer.as_ref().is_some_and(|p|p.belongs_to(scope)) && !producer_ready(&r.producer));
        if st.active.as_ref().and_then(|a|a.agent.as_ref()).is_some_and(|e|Arc::ptr_eq(e.scope(),scope)) {
            st.stop(); // same active ticket; Unknown is never released
        } else if unreturned_producer {
            // A native return is not the relay/history return. Keep the exact
            // unusable producer and permission; a failed ACK must not erase
            // the link merely to make a new Prepare/Allow appear available.
            scope.unused_closed();
        } else if let Some(p)=st.agent_permission.take() { p.close(); }
        st.finish(before);
    }
    pub(crate) fn actions_retry_operation_returned(&self,agent:&Option<Arc<rows::Entry>>,id:&str) {
        let Some(e)=agent else {return};
        let st=&self.actions_retry;
        let Some(o)=st.view.operation.as_ref().filter(|o|o.id==id && o.phase==p::Phase::Settled) else {
            e.unknown(wire::Reason::CleanupUnknown);return;
        };
        let reason=serde_json::to_value(st.view.reason).ok().and_then(|v|v.as_str().map(action_delegation::reason));
        let effect=serde_json::to_value(o.effect).ok().and_then(|v|serde_json::from_value::<wire::Effect>(v).ok());
        let (Some(reason),Some(effect))=(reason,effect) else {e.unknown(wire::Reason::CleanupUnknown);return;};
        let result=(||->Result<Option<wire::operation::Snapshot>,BridgeError>{
            use wire::{dispatch::Hex, operation::{Record,Snapshot}};
            let snapshot=match e.scope().review.kind() {
                wire::Kind::FailedJobsPrepare if reason==wire::Reason::None => {
                    let c=st.consent.as_ref().ok_or_else(no)?;
                    if c.producer.as_ref().is_none_or(|p|!p.belongs_to(e.scope())) { return Err(no()); }
                    Snapshot::Prepared {consent_id:Hex::parse(&c.id).ok_or_else(no)?,prepared_sha256:Hex::parse(&hash(&c.prepared)?).ok_or_else(no)?,next:wire::Kind::FailedJobsRetry}
                }
                wire::Kind::FailedJobsPending if reason==wire::Reason::None => {
                    if st.view.pending.len()>wire::operation::ROWS || st.agent_records.is_none() {return Err(no());}
                    let mut result=Vec::with_capacity(st.view.pending.len());
                    for row in &st.view.pending {
                        result.push(Record {marker:Hex::parse(marker(&row.prepared.target).ok_or_else(no)?).ok_or_else(no)?,
                            record_sha256:Hex::parse(&hash(row)?).ok_or_else(no)?,claimed:row.claimed,acknowledged:row.acknowledged,closed:false});
                    }
                    Snapshot::Pending {rows:result}
                }
                wire::Kind::FailedJobsReconcile => {
                    let observed=st.view.observed.as_ref().map(|v| -> Result<_,BridgeError> {Ok(wire::operation::Observation::FailedJobs {run_id:wire::operation::Number::parse(&v.id).ok_or_else(no)?,attempt:u16::try_from(v.attempt).map_err(|_|no())?})}).transpose()?;
                    let s=Snapshot::Reconciled {marker:Hex::parse(marker(&o.target).ok_or_else(no)?).ok_or_else(no)?,effect,observed};
                    if !s.valid_reason(e.scope().review.kind(),reason) { return Ok(None); }
                    s
                }
                _=>return Ok(None),
            };
            if !snapshot.valid_reason(e.scope().review.kind(),reason) {return Err(no());}
            Ok(Some(snapshot))
        })();
        match result {
            Ok(s)=>e.operation_returned(id,reason,effect,s),
            Err(_)=>e.operation_returned(id,wire::Reason::NativeRefused,effect,None),
        }
    }
}
