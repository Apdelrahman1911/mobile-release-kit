//! Fixed selected originals for ArtifactInspection in the existing SavedCommand
//! registry. OriginalWork still owns every picker/probe/join; no second owner.
use super::*;
use crate::{artifact_inspection_protocol as wire,asset_session::OriginalWork,asset_source::ArtifactProbe};

const ROLES:[wire::Role;3]=[wire::Role::Artifact,wire::Role::Archive,wire::Role::Dsyms];
fn index(role:wire::Role)->usize{match role{wire::Role::Artifact=>0,wire::Role::Archive=>1,wire::Role::Dsyms=>2}}
struct Selected {id:String,proof:Arc<ArtifactProbe>,original:Arc<OriginalWork>}
struct Binding {project_id:String,registration:u32,root:RegisteredRoot,format:wire::Format}
struct Pick {binding:Binding,role:wire::Role,original:Arc<OriginalWork>,first:Option<(wire::SelectionReason,Instant)>,stopping:bool}
pub(super) struct Inputs {
    generation:u32, binding:Option<Binding>, selected:[Option<Selected>;3],
    active:Option<Pick>,unknown:bool,consumed:bool,reason:wire::SelectionReason,
}
impl Default for Inputs {fn default()->Self{Self{generation:0,binding:None,selected:std::array::from_fn(|_|None),active:None,unknown:false,consumed:false,reason:wire::SelectionReason::None}}}
struct LoanMember {id:String,proof:Arc<ArtifactProbe>,original:Arc<OriginalWork>}
/// Non-Serialize: constructed only from the current retained original set.
/// A prepared loan is consumed once by the SAME registry before Session/GO.
pub(crate) struct Loan {generation:u32,project_id:String,registration:u32,root:RegisteredRoot,format:wire::Format,members:[Option<LoanMember>;3]}
impl Loan {
    pub(crate) fn originals_settled(&self)->bool {self.members.iter().flatten().all(|v|v.original.artifact_selected_settled())}
    pub(crate) fn picker_originals(&self)->[Option<Arc<OriginalWork>>;3]{std::array::from_fn(|i|self.members[i].as_ref().map(|v|v.original.clone()))}
    fn matches_context(&self,c:&wire::Context,registration:u32,root:&RegisteredRoot)->bool{
        self.project_id==c.project_id&&self.registration==registration&&self.root==*root&&self.format==c.format
            &&self.members[0].as_ref().is_some_and(|v|v.id==c.selections.artifact)
            &&self.members[1].as_ref().map(|v|v.id.as_str())==c.selections.archive.as_deref()
            &&self.members[2].as_ref().map(|v|v.id.as_str())==c.selections.dsyms.as_deref()
    }
    pub(super) fn result_matches(&self,result:&wire::ResultData)->bool{
        result.artifacts.len()==self.members.iter().flatten().count()&&result.artifacts.iter().all(|row|
            self.members[index(row.role)].as_ref().is_some_and(|v|v.id==row.selection_id&&v.proof.label==row.label&&v.proof.kind==row.kind))
    }
    pub(super) fn wire_originals(&self)->Result<Vec<wire::Original<'_>>,BridgeError>{
        ROLES.into_iter().zip(&self.members).filter_map(|(role,v)|v.as_ref().map(|v|(role,v))).map(|(role,v)|
            Ok(wire::Original{selection_id:&v.id,role,path:v.proof.path.to_str().ok_or_else(wire::invalid)?,kind:v.proof.kind,identity:&v.proof.identity})).collect()
    }
    pub(super) fn retained_data_bytes(&self)->Option<usize>{
        self.members.iter().flatten().try_fold(std::mem::size_of::<Self>().checked_add(self.project_id.capacity())?.checked_add(self.root.path.capacity())?,|sum,v|
            sum.checked_add(v.id.capacity())?.checked_add(std::mem::size_of::<ArtifactProbe>())?.checked_add(v.proof.path.capacity())?.checked_add(v.proof.label.capacity())?.checked_add(v.proof.identity.retained_bytes()?))
    }
}
impl Inputs {
    pub(super) fn busy(&self)->bool{self.active.is_some()}
    pub(super) fn unknown(&self)->bool{self.unknown}
    pub(super) fn registration_matches(&self,generation:u32)->bool{
        self.binding.as_ref().is_none_or(|b|b.registration==generation)&&self.active.as_ref().is_none_or(|p|p.binding.registration==generation)
    }
    fn same_original(&self,o:&Arc<OriginalWork>)->bool{self.active.as_ref().is_some_and(|p|Arc::ptr_eq(&p.original,o))}
    pub(super) fn loan(&self,c:&wire::Context,registration:u32,root:&RegisteredRoot)->Result<Loan,BridgeError>{
        if self.unknown||self.active.is_some()||self.consumed||self.generation==0{return Err(SavedCommandDomain::ArtifactInspection.invalid_owner());}
        let b=self.binding.as_ref().ok_or_else(wire::invalid)?;
        let loan=Loan{generation:self.generation,project_id:b.project_id.clone(),registration:b.registration,root:b.root.clone(),format:b.format,
            members:std::array::from_fn(|i|self.selected[i].as_ref().map(|v|LoanMember{id:v.id.clone(),proof:v.proof.clone(),original:v.original.clone()}))};
        if !loan.matches_context(c,registration,root){return Err(SavedCommandDomain::ArtifactInspection.invalid_owner());} Ok(loan)
    }
    pub(super) fn same_loan(&self,loan:&Loan)->bool{
        !self.unknown&&!self.consumed&&self.active.is_none()&&self.generation==loan.generation
            &&self.binding.as_ref().is_some_and(|b|b.project_id==loan.project_id&&b.registration==loan.registration&&b.root==loan.root&&b.format==loan.format)
            &&self.selected.iter().zip(&loan.members).all(|(a,b)|match(a,b){(None,None)=>true,(Some(a),Some(b))=>a.id==b.id&&Arc::ptr_eq(&a.proof,&b.proof)&&Arc::ptr_eq(&a.original,&b.original),_=>false})
    }
    pub(super) fn consume(&mut self,loan:&Loan)->bool{let matches=self.same_loan(loan);self.consumed=true;matches}
    pub(super) fn status(&self)->wire::Selection{
        let binding=self.binding.as_ref().or_else(||self.active.as_ref().map(|p|&p.binding));
        let phase=if self.unknown{wire::SelectionPhase::Unknown}else if self.active.as_ref().is_some_and(|p|p.first.is_some()||p.stopping){wire::SelectionPhase::Stopping}
            else if self.active.is_some(){wire::SelectionPhase::Picking}else if self.selected.iter().any(Option::is_some){wire::SelectionPhase::Ready}else{wire::SelectionPhase::Idle};
        wire::Selection{generation:self.generation,project_id:binding.map(|b|b.project_id.clone()),format:binding.map(|b|b.format),phase,reason:self.reason,
            operation:self.active.as_ref().map(|p|wire::PickOperation{operation_id:p.original.id,role:p.role}),
            items:ROLES.into_iter().zip(&self.selected).filter_map(|(role,v)|v.as_ref().map(|v|wire::Selected{selection_id:v.id.clone(),role,label:v.proof.label.clone(),kind:v.proof.kind})).collect()}
    }
    pub(super) fn stop(&mut self,reason:wire::SelectionReason,at:Instant)->bool{
        let changed=self.binding.is_some()||self.active.is_some()||self.selected.iter().any(Option::is_some);
        self.consumed=true;self.reason=reason;
        if let Some(p)=self.active.as_mut(){if p.first.is_none_or(|(_,old)|at<old){p.first=Some((reason,at));}p.original.request_artifact_stop();}
        // Retain every settled selected Arc until deliberate discard. In-flight
        // failure never drops an unresolved OriginalWork or fabricates closure.
        changed
    }
    pub(super) fn exhaust(&mut self){self.stop(wire::SelectionReason::CleanupUnknown,Instant::now());self.unknown=true;}
    pub(super) fn census_originals(&self)->Option<[Option<Arc<OriginalWork>>;3]>{
        if self.unknown||self.active.is_some(){return None;} Some(std::array::from_fn(|i|self.selected[i].as_ref().map(|v|v.original.clone())))
    }
    pub(super) fn same_census(&self,values:&[Option<Arc<OriginalWork>>;3])->bool{
        !self.unknown&&self.active.is_none()&&self.selected.iter().zip(values).all(|(a,b)|match(a,b){(None,None)=>true,(Some(a),Some(b))=>Arc::ptr_eq(&a.original,b),_=>false})
    }
    pub(super) fn retained_data_bytes(&self)->Option<usize>{
        if self.unknown||self.active.is_some(){return None;}
        let n=self.binding.as_ref().map_or(Some(0),|b|b.project_id.capacity().checked_add(b.root.path.capacity()))?;
        self.selected.iter().flatten().try_fold(std::mem::size_of::<Self>().checked_add(n)?,|sum,v|sum.checked_add(v.id.capacity())?.checked_add(std::mem::size_of::<ArtifactProbe>())?.checked_add(v.proof.path.capacity())?.checked_add(v.proof.label.capacity())?.checked_add(v.proof.identity.retained_bytes()?))
    }
    pub(super) fn custody_empty(&self)->bool{!self.unknown&&self.active.is_none()&&self.binding.is_none()&&self.selected.iter().all(Option::is_none)}
}
impl SavedCommandOwner {
    pub(crate) fn artifact_inspection(runtime:RuntimeConfig)->Self{Self::new(runtime,SavedCommandDomain::ArtifactInspection)}
    pub(crate) fn artifact_status(&self,gate:wire::Availability)->Result<wire::Status,BridgeError>{self.status(Availability::from_artifact(gate))?.artifact()}
    pub(crate) fn artifact_snapshot(&self,c:&wire::Context,registration:u32,root:&RegisteredRoot)->Result<Arc<Loan>,BridgeError>{
        let r=self.inner.lock(); if self.inner.domain!=SavedCommandDomain::ArtifactInspection{return Err(self.inner.domain.invalid_owner());}
        r.artifact_inputs.loan(c,registration,root).map(Arc::new)
    }
    pub(crate) fn artifact_prepare(&self,input:wire::Prepare,registration:u32,project:RegisteredRoot,checked:&Loan,tools:Option<Arc<ArtifactToolLoan>>,gate:wire::Availability)->Result<wire::Status,BridgeError>{
        if !checked.matches_context(&input,registration,&project){return Err(self.inner.domain.invalid_owner());}
        {let r=self.inner.lock();if !r.artifact_inputs.same_loan(checked){return Err(self.inner.domain.invalid_owner());}}
        self.prepare_bound(Context::ArtifactInspection(input),registration,project,Availability::from_artifact(gate),None,tools)?.artifact()
    }
    pub(crate) fn artifact_start(&self,input:wire::Start,at:Instant,registered:Option<(u32,RegisteredRoot)>,gate:wire::Availability)->Result<ArtifactAdmitted,BridgeError>{
        let admitted=self.start(Start{operation_id:input.operation_id,owner_generation:input.owner_generation},at,registered,Availability::from_artifact(gate))?;
        Ok(ArtifactAdmitted{status:admitted.status.artifact()?,release:admitted.release})
    }
    pub(crate) fn artifact_cancel(&self,input:wire::Cancel,gate:wire::Availability)->Result<wire::Status,BridgeError>{
        self.cancel(&input.operation_id,&input.owner_generation,Availability::from_artifact(gate))?.artifact()
    }
    pub(crate) fn artifact_discard(&self,input:wire::Discard,gate:wire::Availability)->Result<wire::Status,BridgeError>{
        self.reconcile();let mut r=self.inner.lock();
        if self.inner.domain!=SavedCommandDomain::ArtifactInspection||r.disabled||r.exhausted||r.active.is_some()||r.artifact_inputs.busy()||r.artifact_inputs.unknown(){return Err(self.inner.domain.busy());}
        let current=r.prepared.as_ref().map(|p|&p.projection).or(r.last.as_ref());
        if input.selection_generation!=r.artifact_inputs.generation||match(current,input.operation_id.as_deref(),input.owner_generation.as_deref()){
            (None,None,None)=>false,(Some(p),Some(id),Some(generation))=>p.operation_id!=id||p.owner_generation!=generation,_=>true}{return Err(self.inner.domain.invalid_owner());}
        self.inner.retire_prepared(&mut r,Reason::ContextChanged);r.last=None;
        r.artifact_inputs.selected=std::array::from_fn(|_|None);r.artifact_inputs.binding=None;r.artifact_inputs.consumed=true;r.artifact_inputs.reason=wire::SelectionReason::None;
        self.inner.bump(&mut r);self.inner.snapshot_locked(&mut r,Availability::from_artifact(gate))?.artifact()
    }
    pub(crate) fn artifact_admit_pick(&self,input:&wire::Pick,registration:u32,root:RegisteredRoot,original:Arc<OriginalWork>,gate:wire::Availability)->Result<(),BridgeError>{
        let mut r=self.inner.lock();
        let available=self.inner.availability(&r,Availability::from_artifact(gate));
        let prepared_only=available==Availability::Busy&&gate==wire::Availability::Available&&r.prepared.is_some()&&r.active.is_none()
            &&!r.artifact_inputs.busy()&&!r.artifact_inputs.unknown()&&!r.disabled&&!r.exhausted&&!r.stopping&&!r.document_lost;
        if self.inner.domain!=SavedCommandDomain::ArtifactInspection||available!=Availability::Available&&!prepared_only||r.artifact_inputs.busy(){return Err(self.inner.domain.unavailable());}
        if input.format==wire::Format::Aab&&input.role!=wire::Role::Artifact{return Err(wire::invalid());}
        if input.role!=wire::Role::Artifact && (r.artifact_inputs.consumed||!r.artifact_inputs.binding.as_ref().is_some_and(|b|b.project_id==input.project_id&&b.registration==registration&&b.root==root&&b.format==wire::Format::Ipa)
            ||r.artifact_inputs.selected[0].is_none()||input.role==wire::Role::Dsyms&&r.artifact_inputs.selected[1].is_none()){return Err(wire::invalid());}
        if r.artifact_inputs.generation>=u32::MAX-1{r.artifact_inputs.exhaust();r.disabled=true;self.inner.bump(&mut r);return Err(BridgeError::cleanup_unknown());}
        r.artifact_inputs.active=Some(Pick{binding:Binding{project_id:input.project_id.clone(),registration,root,format:input.format},role:input.role,original,first:None,stopping:false});
        r.artifact_inputs.reason=wire::SelectionReason::None;self.inner.bump(&mut r);Ok(())
    }
    pub(crate) fn artifact_pick_stop(&self,o:&Arc<OriginalWork>)->Option<(crate::asset_commands::Reason,Instant)>{
        let r=self.inner.lock();r.artifact_inputs.active.as_ref().filter(|p|Arc::ptr_eq(&p.original,o)).and_then(|p|p.first).map(|(v,at)|
            (match v{wire::SelectionReason::Shutdown=>crate::asset_commands::Reason::Shutdown,wire::SelectionReason::DocumentLost=>crate::asset_commands::Reason::DocumentLost,
            wire::SelectionReason::CleanupUnknown=>crate::asset_commands::Reason::CleanupUnknown,_=>crate::asset_commands::Reason::ContextStale},at))
    }
    pub(crate) fn artifact_publish_pick(&self,o:&Arc<OriginalWork>,proof:ArtifactProbe)->Result<(),BridgeError>{
        if !o.artifact_selected_settled(){return Err(BridgeError::cleanup_unknown());}
        let id=nonce(SavedCommandDomain::ArtifactInspection)?;
        let mut r=self.inner.lock();
        if r.disabled||r.exhausted||r.stopping||r.document_lost||r.artifact_inputs.unknown||!r.artifact_inputs.same_original(o)
            ||r.artifact_inputs.active.as_ref().is_some_and(|p|p.first.is_some()||p.stopping){return Err(self.inner.domain.unavailable());}
        if r.artifact_inputs.selected.iter().flatten().any(|v|v.id==id){return Err(self.inner.domain.unavailable());}
        let next=r.artifact_inputs.generation.checked_add(1).filter(|v|*v<u32::MAX).ok_or_else(BridgeError::cleanup_unknown)?;
        let p=r.artifact_inputs.active.take().ok_or_else(BridgeError::cleanup_unknown)?;
        // Only known accepted replacement invalidates previous consent/result.
        self.inner.retire_prepared(&mut r,Reason::ContextChanged);r.last=None;
        let values=&mut r.artifact_inputs;
        if p.role==wire::Role::Artifact{values.selected=std::array::from_fn(|_|None);}
        if p.role==wire::Role::Archive{values.selected[2]=None;}
        values.selected[index(p.role)]=Some(Selected{id,proof:Arc::new(proof),original:o.clone()});values.binding=Some(p.binding);
        values.generation=next;values.consumed=false;values.reason=wire::SelectionReason::None;self.inner.bump(&mut r);Ok(())
    }
    pub(crate) fn artifact_observe_pick(&self,o:&Arc<OriginalWork>,phase:crate::asset_session::Phase,reason:crate::asset_commands::Reason,unknown:bool){
        use crate::asset_commands::Reason as R;
        let settled=phase==crate::asset_session::Phase::Idle&&o.artifact_refusal_settled();
        let cancel=settled&&reason==R::UserCancelled&&o.artifact_cancel_settled();
        let mut r=self.inner.lock();if !r.artifact_inputs.same_original(o){return;}
        if unknown||phase==crate::asset_session::Phase::Unknown||r.artifact_inputs.unknown {r.artifact_inputs.exhaust();r.disabled=true;}
        else if settled{
            if reason==R::None{r.artifact_inputs.exhaust();r.disabled=true;}
            else{r.artifact_inputs.active=None;r.artifact_inputs.reason=if cancel{wire::SelectionReason::Cancelled}else{match reason{
                R::SourceChanged=>wire::SelectionReason::SourceChanged,R::ContextStale=>wire::SelectionReason::ContextChanged,R::DocumentLost=>wire::SelectionReason::DocumentLost,R::Shutdown=>wire::SelectionReason::Shutdown,
                R::MaterialLimit|R::ParserLimit|R::Capacity=>wire::SelectionReason::InputLimit,_=>wire::SelectionReason::SourceRefused}};}
        }else if phase==crate::asset_session::Phase::Stopping{
            r.artifact_inputs.reason=wire::SelectionReason::SourceRefused;
            // The existing Document slot owns the actual returned-failure cutoff.
            // This is only its displayed phase; never sample a replacement F.
            if let Some(p)=r.artifact_inputs.active.as_mut(){p.stopping=true;}
        }else{return;}
        self.inner.bump(&mut r);
    }
}
pub(crate) struct ArtifactAdmitted{pub(crate) status:wire::Status,release:Option<oneshot::Sender<()>>}
impl ArtifactAdmitted{pub(crate) fn release(self)->wire::Status{if let Some(release)=self.release{let _=release.send(());}self.status}}

/// At this exact cut the original inspection returned; no spawn, child or IO
/// constructor has run. Charge its retained FD ledger plus six stdio ends and
/// two conservative exec-error ends. The same runtime originals are transferred
/// (not reopened); prepare/settle only POST them. No process-wide FD scan/credit.
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn request(owner:&Session,book:&Resources,context:&wire::Context,profile:wire::Profile,runtime:&VerifiedRuntime)->Result<Vec<u8>,BridgeError>{
    if owner.domain!=SavedCommandDomain::ArtifactInspection||!book.artifact_selected||!book.inspection_started||!book.inspection_joined||book.inspection_failed
        ||book.inspection.is_some()||book.inspection_error.is_some()||book.acquisition_started||book.acquisition.is_some()
        ||book.child.is_some()||book.writer.is_some()||book.stdout.is_some()||book.stderr.is_some(){return Err(BridgeError::cleanup_unknown());}
    {let startup=owner.startup.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if startup.attempted||startup.returned||startup.failed||startup.child.is_some(){return Err(BridgeError::cleanup_unknown());}}
    let loan=owner.artifact_selection.as_ref().ok_or_else(BridgeError::protocol)?;
    if !loan.matches_context(context,owner.registration,&owner.project)||!loan.originals_settled(){return Err(BridgeError::cleanup_unknown());}
    let count=book.artifact_installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.try_lock().map_err(|_|BridgeError::cleanup_unknown())?
        .retained_original_count().ok_or_else(BridgeError::cleanup_unknown)?;
    let parent=count.checked_add(8).filter(|n|*n<192).and_then(|n|u32::try_from(n).ok()).ok_or_else(wire::invalid)?;
    let binding=owner.artifact_binding.lock().map_err(|_|BridgeError::cleanup_unknown)?;
    if owner.artifact_tools.is_some()!=binding.is_some()||owner.artifact_tools.as_ref().is_some_and(|v|!v.current()){return Err(BridgeError::cleanup_unknown());}
    wire::request(&owner.id,&owner.generation,context,profile,&owner.project,&runtime.cwd,&loan.wire_originals()?,binding.as_ref(),context.format==wire::Format::Ipa,parent)
}

/// Borrowed quiescent census of the SAME registry; no allocation, resource
/// operation, serialized-size credit, alternate owner, or positive close proof.
pub(crate) struct ArtifactCensus<'a>{registry:std::sync::MutexGuard<'a,Registry>}
impl ArtifactCensus<'_>{
    pub(crate) fn members(&self)->impl Iterator<Item=(&Arc<OriginalWork>,&Arc<ArtifactProbe>)>{
        self.registry.artifact_inputs.selected.iter().flatten().map(|v|(&v.original,&v.proof))
    }
    pub(crate) fn data_bytes(&self)->Option<usize>{
        let values=&self.registry.artifact_inputs;
        let mut n=std::mem::size_of::<Inputs>();
        if let Some(b)=&values.binding{n=n.checked_add(b.project_id.capacity())?.checked_add(b.root.path.capacity())?;}
        for v in values.selected.iter().flatten(){n=n.checked_add(v.id.capacity())?;}
        if let Some(p)=&self.registry.last{
            let Context::ArtifactInspection(c)=&p.context else{return None;};
            if p.stage.is_some(){return None;}
            n=n.checked_add(p.operation_id.capacity())?.checked_add(p.owner_generation.capacity())?.checked_add(c.retained_heap_bytes()?)?;
            if let Some(t)=&p.result{let Terminal::ArtifactInspection(t)=t else{return None;};n=n.checked_add(t.retained_heap_bytes()?)?;}
        }
        Some(n)
    }
}
impl SavedCommandOwner{
    pub(crate) fn artifact_census(&self)->Result<ArtifactCensus<'_>,BridgeError>{
        if self.inner.domain!=SavedCommandDomain::ArtifactInspection||self.inner.poisoned.load(Ordering::SeqCst){return Err(BridgeError::cleanup_unknown());}
        let r=self.inner.registry.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if r.disabled||r.exhausted||r.stopping||r.document_lost||r.active.is_some()||r.prepared.is_some()||r.artifact_inputs.unknown()||r.artifact_inputs.busy(){return Err(BridgeError::cleanup_unknown());}
        // A missing slot/identity is not an empty original. Fixed transport
        // invariants remain checked even when consumed selections are retained.
        if r.artifact_inputs.binding.is_some()!=r.artifact_inputs.selected[0].is_some()
            ||r.artifact_inputs.selected[2].is_some()&&r.artifact_inputs.selected[1].is_none(){return Err(BridgeError::cleanup_unknown());}
        Ok(ArtifactCensus{registry:r})
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn missing_original_table_cannot_be_loaned_or_consumed_and_metadata_census_is_checked(){
        let mut inputs=Inputs::default();let c=wire::tests::context();
        let root=RegisteredRoot{path:"/inert-artifact-project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        assert!(inputs.loan(&c,1,&root).is_err());
        let fake=Loan{generation:0,project_id:c.project_id.clone(),registration:1,root:root.clone(),format:c.format,members:std::array::from_fn(|_|None)};
        assert!(!inputs.consume(&fake));assert!(inputs.consumed);
        assert!(inputs.custody_empty());assert!(inputs.retained_data_bytes().unwrap()>=std::mem::size_of::<Inputs>());
        inputs.binding=Some(Binding{project_id:c.project_id.clone(),registration:1,root,format:c.format});
        inputs.generation=1;inputs.consumed=false;
        assert!(inputs.loan(&c,1,&fake.root).is_err());
        assert!(!inputs.custody_empty());
        let before=inputs.generation;inputs.stop(wire::SelectionReason::ContextChanged,Instant::now());
        assert_eq!(inputs.generation,before);assert!(inputs.consumed);
        assert_eq!(inputs.status().reason,wire::SelectionReason::ContextChanged);
        inputs.exhaust();assert!(inputs.unknown());assert!(inputs.census_originals().is_none());
        assert!(inputs.retained_data_bytes().is_none());
        // Exercise the actual owner predicate against its actual fixed picker
        // cell. This New OriginalWork is not a fabricated returned GUI proof.
        let application=SavedCommandOwner::artifact_inspection(RuntimeConfig::packaged("/unopened-artifact-runtime".into()));
        assert!(application.can_exit());
        let original=OriginalWork::artifact_unentered_original_data();
        assert!(!original.artifact_selected_settled());
        {let mut r=application.inner.lock();r.artifact_inputs.active=Some(Pick{
            binding:Binding{project_id:c.project_id.clone(),registration:1,root:fake.root.clone(),format:c.format},
            role:wire::Role::Artifact,original:original.clone(),first:None,stopping:false});}
        assert!(!application.can_exit());application.request_shutdown();assert!(!application.can_exit());
        {let mut r=application.inner.lock();assert!(r.artifact_inputs.active.as_ref().unwrap().first.is_some());
            r.artifact_inputs.active=None;r.artifact_inputs.unknown=true;}
        assert!(!application.can_exit());
        // Historical metadata is a DIFFERENT healthy original owner: the
        // unknown owner above stays permanently fenced by its real reconciler.
        // This is only can-exit DATA, never native settlement admission.
        let application=SavedCommandOwner::artifact_inspection(RuntimeConfig::packaged("/unopened-artifact-metadata-runtime".into()));
        {let mut r=application.inner.lock();
            r.artifact_inputs.binding=Some(Binding{project_id:c.project_id.clone(),registration:1,root:fake.root.clone(),format:c.format});
            r.artifact_inputs.generation=1;r.artifact_inputs.consumed=true;
            r.artifact_inputs.selected[0]=Some(Selected{id:c.selections.artifact.clone(),original,
                proof:Arc::new(ArtifactProbe{path:"/unopened-artifact.ipa".into(),label:"unopened-artifact.ipa".into(),kind:wire::Kind::File,
                    identity:wire::OriginalIdentity{device:"1".into(),inode:"2".into(),mode:0o100600,uid:501,gid:20,nlink:"1".into(),bytes:"1".into(),
                        mtime_seconds:"0".into(),mtime_nanos:0,ctime_seconds:"0".into(),ctime_nanos:0,flags:0}})});}
        assert!(application.can_exit());assert!(!application.inner.lock().artifact_inputs.custody_empty());
    }
}
