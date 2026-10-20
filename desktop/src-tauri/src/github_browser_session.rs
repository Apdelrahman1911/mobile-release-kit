//! Synchronous selection from the same original ConnectionState, never renderer URLs.
use super::*;
use crate::{asset_source::RegisteredRoot, edit_owner::SavedEditGuard,
    github_browser_protocol as b, github_activity_protocol as a, github_pull_request_protocol as p};

impl ConnectionState {
    pub(crate) fn github_browser_destination(&mut self, request:&b::Request, generation:u32,
        root:&RegisteredRoot, binding:&str, edit:&SavedEditGuard<'_>, now:Instant,
        activity_qualified:bool, pr_qualified:bool) -> Result<b::Destination,BridgeError> {
        if self.unknown || self.exhausted || self.native_work_pending() { return Err(b::refused()); }
        let original=self.private.as_ref().filter(|s|s.id==request.session()&&s.generation==generation
            &&s.retirement.is_none()&&s.token.is_some()&&now<s.clock.end).ok_or_else(b::refused)?;
        if self.status.revision!=request.connection_revision()
            || !self.status.session.as_ref().is_some_and(|s|s.id==original.id&&s.project_id==original.project_id&&s.state==SessionState::Connected)
            || self.status.account.state!=FactState::Observed || self.status.repository.state!=FactState::Observed {return Err(b::refused());}
        let account=self.status.account.value.as_ref().filter(|a|Some(&a.id)==original.account_pin.as_ref()).ok_or_else(b::refused)?;
        let repo=self.status.repository.value.as_ref().filter(|r|Some(&r.id)==original.repository_pin.as_ref()
            &&r.full_name.eq_ignore_ascii_case(&original.repository)).ok_or_else(b::refused)?;
        let (account_id,repository_id,repository,project)=(account.id.clone(),repo.id.clone(),repo.full_name.clone(),original.project_id.clone());
        let matches=|project_binding:&str,r:&str,aid:&str,rid:&str|project_binding==binding&&r.eq_ignore_ascii_case(&repository)&&aid==account_id&&rid==repository_id;
        let target=match request {
            b::Request::ActivityPullRequest{operation_id,page,..} => {
                let status=self.github_activity_status(activity_qualified,now,Reason::None);
                let o=status.operation.as_ref().ok_or_else(b::refused)?;
                let r=status.result.as_ref().ok_or_else(b::refused)?;
                let a::Selection::PullRequest{number}=&r.selection else{return Err(b::refused());};
                if !status.available||status.revision!=request.revision()||status.session_id.as_deref()!=Some(request.session())
                    ||o.id!=*operation_id||o.project_id!=project||o.phase!=a::Phase::Settled||o.reason!=a::Reason::None
                    ||o.selection!=r.selection||o.target!=r.target
                    ||!matches(&r.target.project_binding,&r.target.repository,&r.target.account_id,&r.target.repository_id) {return Err(b::refused());}
                b::Destination::PullRequest{repository:r.target.repository.clone(),number:number.clone(),page:*page}
            },
            b::Request::CreatedPullRequest{operation_id,page,..} => {
                let status=self.pull_request_status(pr_qualified,now,Reason::None);
                let o=status.operation.as_ref().ok_or_else(b::refused)?;
                let ack=status.acknowledged.as_ref().or(status.observed.as_ref()).ok_or_else(b::refused)?;
                if !status.available||status.revision!=request.revision()||status.session_id.as_deref()!=Some(request.session())
                    ||o.id!=*operation_id||o.project_id!=project||o.phase!=p::Phase::Settled||!matches!(o.kind,p::Kind::Create|p::Kind::Reconcile)
                    ||!matches(&o.target.scope.project_binding,&o.target.scope.repository,&o.target.scope.account_id,&o.target.scope.repository_id)
                    ||!crate::github_connection_protocol::numeric_id(&ack.id)
                    ||ack.url!=format!("https://github.com/{}/pull/{}",o.target.scope.repository,ack.number) {return Err(b::refused());}
                b::Destination::PullRequest{repository:o.target.scope.repository.clone(),number:ack.number.clone(),page:*page}
            },
            b::Request::Comparison{consent_id,..} => {
                let status=self.pull_request_status(pr_qualified,now,Reason::None);
                if !status.available||status.revision!=request.revision()||status.session_id.as_deref()!=Some(request.session()) {return Err(b::refused());}
                // The full original native review retains its root/edit stamp,
                // draft and deadline. Public ConsentView alone is insufficient.
                self.pull_request_browser_comparison(consent_id,&project,generation,root,edit,now)?
            },
        };
        if !target.valid(){return Err(b::refused());}
        Ok(target)
    }
}
