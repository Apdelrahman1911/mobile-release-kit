// Same-Book maintenance recovery. No worker result is reconstructed: a torn
// invocation stays preserved, and only a new worker can create a new capsule.
use super::*;
use transaction::{NoopRecoveryData, NoopStatePlacementData, RecoveryReferenceData};
use mobile_release_desktop::macos_applications_launcher::OriginalIdentityData;

const RECEIPT_LIMIT:usize=transaction::INTENT_LIMIT+8192;
fn quote_data(attempts:usize)->Result<(u64,usize)> {
    check((1..=transaction::INVOCATION_LIMIT).contains(&attempts),"noop-recovery-attempt-bound")?;
    let control=attempts.checked_mul((transaction::INTENT_LIMIT+transaction::STATE_LIMIT)*8)
        .and_then(|n|n.checked_add(4*RECEIPT_LIMIT)).ok_or("noop-recovery-memory")?;
    let originals=attempts.checked_mul(12).and_then(|n|n.checked_add(32)).ok_or("noop-recovery-original-bound")?;
    Ok((control as u64,originals))
}

#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Receipt {
    schema_version:u32,kind:String,target:String,stage_invocation:String,torn_intent:String,
    previous_state_sha256:String,previous_capsule_sha256:String,
    root:OriginalIdentityData,stage:OriginalIdentityData,
    old_state:OriginalIdentityData,
}
fn original(book:&Install,n:usize)->Result<OriginalIdentityData> {
    let expected=book.identity(n)?;
    let directory=expected.mode&u32::from(SFlag::S_IFMT.bits())==u32::from(SFlag::S_IFDIR.bits());
    // Existing root/stage originals acquire children under the SAME M. Their
    // directory times change, as in the enrolled launcher phase container;
    // file originals still require full metadata equality.
    book.check_name(n,!directory)?;
    let s=stat::fstat(book.fd(n)?).map_err(|_|"noop-recovery-original-stat")?;
    check(!directory || u32::from(s.st_mode)==expected.mode && s.st_uid==expected.uid
        && s.st_gid==expected.gid,"noop-recovery-container-metadata")?;
    let row=&book.originals[n];let named=book.named(row.parent,&row.name).map_err(|_|"noop-recovery-original-name")?;
    let value=OriginalIdentityData{device:i64::from(s.st_dev),inode:s.st_ino,
        birth_seconds:s.st_birthtime,birth_nanoseconds:s.st_birthtime_nsec};
    check(value.valid_data() && Identity::of(&s)==Identity::of(&named)
        && s.st_birthtime==named.st_birthtime && s.st_birthtime_nsec==named.st_birthtime_nsec
        && s.st_flags==0 && named.st_flags==0,"noop-recovery-original-identity")?;Ok(value)
}
fn exact_invocation(name:&str)->Option<&str> {
    let id=name.strip_prefix(".maintenance-")?.strip_suffix(".intent.json")?;
    worker::invocation_valid(id).then_some(id)
}
fn optional_file(book:&mut Install,parent:usize,name:&str,limit:usize,prefix:bool)->Result<Option<(usize,Vec<u8>)>> {
    match book.named(Some(parent),name) {Err(Errno::ENOENT)=>return Ok(None),Err(_)=>return Err("noop-recovery-name"),Ok(_)=>{}}
    if !prefix {return metadata_original(book,parent,name,limit).map(Some);}
    let n=book.open(Some(parent),name,false)?;let s=stat::fstat(book.fd(n)?).map_err(|_|"noop-recovery-prefix-stat")?;
    let mode=u32::from(s.st_mode)&0o7777;
    check(matches!(mode,0o600|0o444) && s.st_flags==0 && s.st_size>=0 && s.st_size as u64<=limit as u64,
        "noop-recovery-prefix-bound")?;
    book.protected(n,false,Some(mode))?;native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"noop-recovery-prefix-attributes")?;
    let bytes=book.read(n,s.st_size as u64,true)?.1;
    book.check_name(n,true)?;Ok(Some((n,bytes)))
}
fn reserve(book:&mut Install,attempts:usize)->Result<()> {
    let (control_quote,original_quote)=quote_data(attempts)?;
    check(removal_effective_control_bytes(book)?.checked_add(control_quote)
        .is_some_and(|n|n<=installation_record::CONTROL_LIMIT as u64),"noop-recovery-memory")?;
    let end=book.originals.len().checked_add(original_quote)
        .filter(|n|*n<=installation_record::ORIGINAL_LIMIT).ok_or("noop-recovery-original-bound")?;
    check(book.originals.iter().filter(|r|r.fd.is_some()).count()+book.removal_live_reserved+12<=96,
        "noop-recovery-live-bound")?;
    // Debit DATA backing BEFORE original-vector reservation; that reservation
    // must fit alongside it, not allocate first against a temporarily low sum.
    book.removal_control_reserved=book.removal_control_reserved.checked_add(control_quote)
        .ok_or("noop-recovery-memory")?;
    reserve_removal_original_storage(book,end)?;Ok(())
}
struct Attempt { intent:IntentData,raw:Vec<u8>,identity:OriginalIdentityData,at_root:bool }
pub(super) struct Observation {
    root:usize,stage:usize,root_names:BTreeSet<String>,receipt:Option<(usize,Vec<u8>)>,receipt_data:Receipt,receipt_bytes:Vec<u8>,
    reference:RecoveryReferenceData,base_raw:Vec<u8>,base:IntentData,
    attempts:Vec<Attempt>,old_state:OriginalIdentityData,
    pending:Option<(usize,Vec<u8>)>,placement:NoopStatePlacementData,
    state_attempt:Option<usize>,first:Option<&'static str>,returned:ReturnedData,settled:bool,
}
fn known(history:&History,id:&str)->bool {id==history.current.state.invocation_data()||history.originals.contains_key(id)}
fn recorded_previous<'a>(history:&'a History,id:&str,sha:&str)->Result<&'a Recorded> {
    let record=if id==history.current.state.invocation_data(){&history.current}
        else{history.originals.get(id).ok_or("noop-recovery-old-history")?};
    check(record.state.digest_data()==sha,"noop-recovery-old-history-binding")?;Ok(record)
}
fn parse_receipt(raw:&[u8],selected:&ReleaseSetData,history:&History)->Result<(Receipt,IntentData)> {
    check(!raw.is_empty()&&raw.len()<=RECEIPT_LIMIT,"noop-recovery-receipt-bound")?;
    let value=mobile_release_desktop::protocol::strict_json(raw).map_err(|_|"noop-recovery-receipt-shape")?;
    let receipt:Receipt=serde_json::from_value(value).map_err(|_|"noop-recovery-receipt-shape")?;
    let base=data(IntentData::parse_recorded_data(receipt.torn_intent.as_bytes(),selected))?;
    let (id,sha)=base.previous_state_data().ok_or("noop-recovery-prior-required")?;
    let old=recorded_previous(history,id,sha)?;
    let prior=(&old.state,&old.capsule);
    let expected=data(NoopRecoveryData::from_recorded_data(&base,prior,selected))?;
    check(receipt.schema_version==1 && receipt.kind=="mrk-noop-original-preservation-v1"
        && receipt.target==selected.target_data().target() && base.recovery_data().is_none()
        && receipt.stage_invocation==expected.stage_invocation_data()
        && receipt.previous_state_sha256==prior.0.digest_data() && receipt.previous_capsule_sha256==prior.1.digest_data()
        && [receipt.root,receipt.stage,receipt.old_state].into_iter().all(|i|i.valid_data()),
        "noop-recovery-receipt-binding")?;
    let mut encoded=serde_json::to_vec(&receipt).map_err(|_|"noop-recovery-receipt-shape")?;encoded.push(b'\n');
    check(encoded==raw,"noop-recovery-receipt-canonical")?;Ok((receipt,base))
}
// Read a COMPLETE previous history from its observed State original, not a
// invented capsule. Missing current capsule is only a nomination to inspect
// its explicit Noop previous link; all other history failures remain failures.
pub(super) fn history_candidate(book:&mut Install,root:usize,selected:&ReleaseSetData)->Result<History> {
    let (current,raw)=metadata_original(book,root,transaction::STATE_NAME,transaction::STATE_LIMIT)?;
    let state=data(StateData::parse_data(&raw,selected))?;
    let cap=data(transaction::capsule_name_data(state.invocation_data()))?;
    match book.named(Some(root),&cap) {
        Ok(_)=>read_history_original(book,root,selected,current,raw),
        Err(Errno::ENOENT)=>{
            let intent_raw=metadata_bytes(book,root,&data(transaction::intent_name_data(state.invocation_data()))?,transaction::INTENT_LIMIT)?;
            let torn=data(IntentData::parse_data(&intent_raw,selected))?;
            check(torn.action_data()==ActionData::SamePackageNoop && torn.invocation_data()==state.invocation_data(),
                "noop-recovery-original-noop-required")?;
            let (previous,sha)=torn.previous_state_data().ok_or("noop-recovery-prior-required")?;
            let (old,old_raw)=metadata_original(book,root,&data(transaction::archived_state_name_data(previous))?,transaction::STATE_LIMIT)?;
            check(hash(&old_raw)==sha,"noop-recovery-old-state")?;
            let history=read_history_original(book,root,selected,old,old_raw)?;
            let expected=data(NoopRecoveryData::from_recorded_data(&torn,(&history.current.state,&history.current.capsule),selected))?;
            check(raw==expected.expected_state_data(),"noop-recovery-torn-state")?;
            held_bytes(book,current,&raw)?;book.forward_close(current,"noop-recovery-canonical-close")?;Ok(history)
        },
        Err(_)=>Err("noop-recovery-current-capsule-name"),
    }
}
impl Observation {
    // This snapshot does not restore anything. It retains exact original bytes
    // and chooses only the closed previous completed generation; the enclosing
    // observer must still perform its full core/producer/namespace audits.
    pub(super) fn capture(book:&mut Install,root:usize,selected:&ReleaseSetData,history:&History,
        pending_intent:Option<&str>)->Result<Option<Self>> {
        let names=roster_now(book,root)?;
        let candidates:Vec<String>=names.keys().filter_map(|name|exact_invocation(name))
            .filter(|id|!known(history,id)&&Some(*id)!=pending_intent).map(str::to_owned).collect();
        let pending_reference=if candidates.is_empty() {
            if let Some(id)=pending_intent {
                reserve(book,1)?;
                let raw=metadata_bytes(book,root,&data(transaction::intent_name_data(id))?,transaction::INTENT_LIMIT)?;
                let intent=data(IntentData::parse_data(&raw,selected))?;
                check(intent.invocation_data()==id,"noop-recovery-current-intent")?;
                intent.recovery_data().cloned()
            }else{None}
        }else{None};
        if candidates.is_empty() && pending_reference.is_none() {return Ok(None);}
        check(candidates.len().checked_add(history.originals.len()+2)
            .is_some_and(|n|n<=transaction::INVOCATION_LIMIT),"noop-recovery-attempt-bound")?;
        if !candidates.is_empty(){reserve(book,candidates.len())?;}
        let mut attempts=Vec::new();let mut nominated:Option<RecoveryReferenceData>=pending_reference;
        let mut base_raw=None;
        let mut requests:BTreeSet<String>=history.originals.values().chain(std::iter::once(&history.current))
            .map(|r|r.intent.request_id_data().into()).collect();
        for invocation in candidates {
            book.absent(root,&data(transaction::capsule_name_data(&invocation))?)?;
            let (reader,raw)=metadata_original(book,root,&data(transaction::intent_name_data(&invocation))?,transaction::INTENT_LIMIT)?;
            let intent=data(IntentData::parse_data(&raw,selected))?;
            check(intent.invocation_data()==invocation && requests.insert(intent.request_id_data().into()),"noop-recovery-attempt-binding")?;
            let _=data(NoopRecoveryData::from_recorded_data(&intent,(&history.current.state,&history.current.capsule),selected))?;
            if let Some(reference)=intent.recovery_data() {
                check(nominated.as_ref().is_none_or(|old|old==reference),"noop-recovery-distinct-references")?;
                nominated=Some(reference.clone());
            }else{
                check(base_raw.is_none(),"noop-recovery-distinct-torn-intents")?;base_raw=Some(raw.clone());
            }
            let identity=original(book,reader)?;held_bytes(book,reader,&raw)?;
            book.forward_close(reader,"noop-recovery-attempt-close")?;
            attempts.push(Attempt{intent,raw,identity,at_root:true});
        }
        let instance=history.current.state.current_data().instance_data().to_owned();
        let stage=book.open(Some(root),&format!(".install-{instance}"),true)?;
        book.protected(stage,true,Some(0o700))?;native::no_xattrs(book.fd(stage)?.as_fd()).map_err(|_|"noop-recovery-stage-attributes")?;
        let root_identity=original(book,root)?;let stage_identity=original(book,stage)?;
        let old_state=original(book,history.state_original)?;
        // When the first recovery already preserved the base intent, its bytes
        // come only from the exact reference-nominated receipt, never a search.
        let stored=if let Some(reference)=&nominated {
            check(reference.stage_invocation_data()==instance,"noop-recovery-reference-stage")?;
            optional_file(book,stage,&reference.receipt_name_data(),RECEIPT_LIMIT,true)?
        }else{None};
        let mut receipt=stored;
        if base_raw.is_none() {
            let (_,body)=receipt.as_ref().ok_or("noop-recovery-base-receipt-required")?;
            let (parsed,_)=parse_receipt(body,selected,history)?;
            check(hash(body)==nominated.as_ref().ok_or("noop-recovery-reference")?.receipt_sha256_data(),
                "noop-recovery-receipt-digest")?;
            base_raw=Some(parsed.torn_intent.into_bytes());
        }
        let base_raw=base_raw.ok_or("noop-recovery-base-intent")?;
        let base=data(IntentData::parse_data(&base_raw,selected))?;
        check(base.recovery_data().is_none()&&!known(history,base.invocation_data()),"noop-recovery-base-intent")?;
        let _=data(NoopRecoveryData::from_recorded_data(&base,(&history.current.state,&history.current.capsule),selected))?;
        let receipt_data=Receipt {schema_version:1,kind:"mrk-noop-original-preservation-v1".into(),
            target:selected.target_data().target().into(),stage_invocation:instance.clone(),
            torn_intent:String::from_utf8(base_raw.clone()).map_err(|_|"noop-recovery-base-utf8")?,
            previous_state_sha256:history.current.state.digest_data().into(),
            previous_capsule_sha256:history.current.capsule.digest_data().into(),
            root:root_identity,stage:stage_identity,old_state};
        let mut receipt_bytes=serde_json::to_vec(&receipt_data).map_err(|_|"noop-recovery-receipt-shape")?;receipt_bytes.push(b'\n');
        check(receipt_bytes.len()<=RECEIPT_LIMIT,"noop-recovery-receipt-bound")?;
        let reference=data(RecoveryReferenceData::new_data(&instance,base.invocation_data(),&hash(&receipt_bytes)))?;
        check(nominated.as_ref().is_none_or(|n|n==&reference),"noop-recovery-receipt-originals")?;
        if receipt.is_none(){receipt=optional_file(book,stage,&reference.receipt_name_data(),RECEIPT_LIMIT,true)?;}
        if let Some((reader,body))=&receipt {
            check(receipt_bytes.starts_with(body),"noop-recovery-receipt-prefix")?;
            let sealed=book.identity(*reader)?.mode & 0o7777==0o444;
            check(!sealed||body==&receipt_bytes,"noop-recovery-sealed-receipt")?;
            // A prefix is never recovery authority by itself: a complete live
            // new Intent must already nominate this exact expected receipt.
            check(body==&receipt_bytes||nominated.is_some(),"noop-recovery-unowned-prefix")?;
        }
        // A prior recovery may already have moved some or all torn intents.
        // Resume only exact reference-bound originals, refusing simultaneous
        // root/stage copies rather than choosing the more convenient spelling.
        let stage_names=roster_now(book,stage)?;
        let mut preserved=Vec::new();
        for name in stage_names.keys() {
            if let Some((id,"intent"))=preserved_role(&reference,name)? {preserved.push((id.to_owned(),name.clone()));}
        }
        check(attempts.len().checked_add(preserved.len()).and_then(|n|n.checked_add(history.originals.len()+2))
            .is_some_and(|n|n<=transaction::INVOCATION_LIMIT),"noop-recovery-aggregate-attempts")?;
        if !preserved.is_empty(){reserve(book,preserved.len())?;}
        for (id,name) in preserved {
            check(!known(history,&id) && attempts.iter().all(|a|a.intent.invocation_data()!=id),
                "noop-recovery-duplicate-attempt-placement")?;
            let (reader,raw)=metadata_original(book,stage,&name,transaction::INTENT_LIMIT)?;
            let intent=data(IntentData::parse_data(&raw,selected))?;
            check(intent.invocation_data()==id && requests.insert(intent.request_id_data().into())
                && (if id==base.invocation_data(){raw==base_raw&&intent.recovery_data().is_none()}
                    else{intent.recovery_data()==Some(&reference)}),"noop-recovery-preserved-intent")?;
            let _=data(NoopRecoveryData::from_recorded_data(&intent,(&history.current.state,&history.current.capsule),selected))?;
            let identity=original(book,reader)?;held_bytes(book,reader,&raw)?;
            book.forward_close(reader,"noop-recovery-preserved-intent-close")?;
            attempts.push(Attempt{intent,raw,identity,at_root:false});
        }
        check(attempts.iter().filter(|a|a.intent.invocation_data()==base.invocation_data()).count()==1,
            "noop-recovery-base-placement")?;
        let archive_name=data(transaction::archived_state_name_data(history.current.state.invocation_data()))?;
        let (canonical,canonical_bytes)=metadata_original(book,root,transaction::STATE_NAME,transaction::STATE_LIMIT)?;
        let mut pending=optional_file(book,root,&archive_name,transaction::STATE_LIMIT,true)?;
        let mut placement=None;let mut state_attempt=None;
        for (index,attempt) in attempts.iter().enumerate() {
            let derived=data(NoopRecoveryData::from_recorded_data(&attempt.intent,(&history.current.state,&history.current.capsule),selected))?;
            if let Ok(candidate)=derived.state_placement_data(&history.state_bytes,&canonical_bytes,
                pending.as_ref().map(|(_,body)|body.as_slice())) {
                check(placement.is_none_or(|old|old==candidate),"noop-recovery-state-ambiguity")?;
                placement=Some(candidate);state_attempt=Some(index);
            }
        }
        let placement=placement.ok_or("noop-recovery-state-placement")?;
        match placement {
            NoopStatePlacementData::Swapped=>{
                let (old,body)=pending.take().ok_or("noop-recovery-old-state")?;
                check(original(book,old)?==old_state && body==history.state_bytes,"noop-recovery-old-original")?;
                book.forward_close(old,"noop-recovery-old-alias-close")?;
                pending=Some((canonical,canonical_bytes));
            },
            _=>{
                check(original(book,canonical)?==old_state,"noop-recovery-old-original")?;
                held_bytes(book,canonical,&canonical_bytes)?;book.forward_close(canonical,"noop-recovery-current-alias-close")?;
                if let Some((reader,body))=&pending {
                    check(book.identity(*reader)?.mode&0o7777!=0o444 || attempts.iter().any(|a|
                        NoopRecoveryData::from_recorded_data(&a.intent,(&history.current.state,&history.current.capsule),selected)
                            .is_ok_and(|r|r.expected_state_data()==body)),"noop-recovery-sealed-pending-state")?;
                }
            },
        }
        Ok(Some(Self{root,stage,root_names:names.keys().cloned().collect(),receipt,receipt_data,receipt_bytes,reference,base_raw,base,attempts,old_state,
            pending,placement,state_attempt,first:None,returned:ReturnedData::KnownRefusal,settled:false}))
    }
}
// Exact preserved prefixes retain their mode and bytes. This helper never
// seals, truncates or deletes an earlier writer's original.
fn file_post(book:&Install,n:usize,expected:&[u8])->Result<()> {
    book.check_name(n,true)?;
    check(expected.len()<=RECEIPT_LIMIT.max(transaction::STATE_LIMIT)
        && book.identity(n)?.size==expected.len() as i64,"noop-recovery-file-extent")?;
    if expected.is_empty() {
        let mut one=[0u8;1];
        check(nix::sys::uio::pread(book.fd(n)?,&mut one,0).map_err(|_|"noop-recovery-prefix-read")?==0,
            "noop-recovery-prefix-extent")?;
        book.clock()?;book.check_name(n,true)
    }else{held_bytes(book,n,expected)}
}
impl Observation {
    pub(super) fn reference(&self)->&RecoveryReferenceData {&self.reference}
    fn post(&self,book:&Install,history:&History)->Result<()> {
        check(original(book,self.root)?==self.receipt_data.root && original(book,self.stage)?==self.receipt_data.stage
            && original(book,history.state_original)?==self.old_state
            && self.receipt_data.previous_state_sha256==history.current.state.digest_data()
            && self.receipt_data.previous_capsule_sha256==history.current.capsule.digest_data(),
            "noop-recovery-same-originals")?;
        held_bytes(book,history.state_original,&history.state_bytes)?;
        if let Some((n,raw))=&self.receipt {file_post(book,*n,raw)?;}
        book.clock()
    }
    fn fail(&mut self,why:&'static str)->&'static str {*self.first.get_or_insert(why)}
    fn move_file(&mut self,book:&mut Install,n:usize,from:usize,name:&str,to:usize,destination:&str,
        bytes:&[u8])->Result<()> {
        if let Some(why)=self.first{return Err(why);}
        let result=(||{
            book.clock()?;file_post(book,n,bytes)?;
            let before=book.identity(n)?;let mode=before.mode&0o7777;
            check(matches!(mode,0o444|0o600) && book.originals[n].parent==Some(from)
                && book.originals[n].name==name && before.dev==book.identity(from)?.dev
                && before.dev==book.identity(to)?.dev,"noop-recovery-move-original")?;
            book.protected(n,false,Some(mode))?;book.check_name(from,false)?;book.check_name(to,false)?;
            book.absent(to,destination)?;
            match native::publish_directory(book.fd(from)?.as_fd(),name,book.fd(to)?.as_fd(),destination) {
                Ok(())=>self.returned=ReturnedData::KnownSuccess,
                Err(error)=>{
                    self.returned=if error.raw_os_error()==Some(Errno::EEXIST as i32){ReturnedData::KnownRefusal}
                        else{book.unknown=true;ReturnedData::Unknown};
                    return Err("noop-recovery-exclusive-move");
                },
            }
            // Returned effect is already latched before every possible POST.
            let actual=stat::fstat(book.fd(n)?).map_err(|_|"noop-recovery-move-stat")?;
            let named=book.named(Some(to),destination).map_err(|_|"noop-recovery-move-name")?;
            check(actual.st_flags==0 && named.st_flags==0 && Identity::of(&actual)==Identity::of(&named)
                && same_renamed(before,Identity::of(&actual)),"noop-recovery-move-identity")?;
            book.originals[n].parent=Some(to);book.originals[n].name=destination.into();
            book.originals[n].identity=Some(Identity::of(&actual));
            book.protected(n,false,Some(mode))?;
            native::no_xattrs(book.fd(n)?.as_fd()).map_err(|_|"noop-recovery-move-attributes")?;
            book.absent(from,name)?;file_post(book,n,bytes)?;
            book.persist(from,false)?;if from!=to{book.persist(to,false)?;}
            file_post(book,n,bytes)
        })();
        result.map_err(|why|self.fail(why))
    }
    // Called after the NEW intent is durably created by the existing parent,
    // before sending GO. Its reference is deterministic; the receipt never
    // claims the earlier worker's exit, and recovery does not inherit its lease.
    pub(super) fn prepare_receipt(&mut self,book:&mut Install,history:&History,new_intent:&IntentData,
        new_original:usize,new_raw:&[u8])->Result<()> {
        let result=(||{
            check(book.gate.verified && book.gate.exclusive_acquired && !book.worker_stderr_is_gate
                && new_intent.recovery_data()==Some(&self.reference)
                && new_intent.action_data()==ActionData::SamePackageNoop,
                "noop-recovery-parent-intent-required")?;
            held_bytes(book,new_original,new_raw)?;
            check(hash(new_raw)==new_intent.digest_data(),"noop-recovery-parent-intent-binding")?;
            self.post(book,history)?;
            let name=self.reference.receipt_name_data();
            if let Some((reader,raw))=self.receipt.take() {
                if raw==self.receipt_bytes && book.identity(reader)?.mode&0o7777==0o444 {
                    self.receipt=Some((reader,raw));return self.post(book,history);
                }
                // Preserve an admitted earlier prefix; do not complete an old
                // writer, overwrite a collision or assign it successful finality.
                let saved=data(self.reference.preserved_name_data(new_intent.invocation_data(),"receipt-prefix"))?;
                let moved=self.move_file(book,reader,self.stage,&name,self.stage,&saved,&raw);
                if let Err(why)=moved {self.receipt=Some((reader,raw));return Err(why);}
                book.forward_close(reader,"noop-recovery-prefix-close")?;
            }
            book.absent(self.stage,&name)?;
            let reader=book.record_file(self.stage,&name,&self.receipt_bytes,Role::ReceiptWriter)?;
            self.receipt=Some((reader,self.receipt_bytes.clone()));
            book.persist(self.stage,false)?;self.post(book,history)
        })();
        result.map_err(|why|self.fail(why))
    }
    // This is invoked only after the original worker GO and records its own
    // actual effects. It restores the held OLD State, not the old worker's
    // outcome, then allows a genuinely new ordinary Noop to run.
    pub(super) fn preserve_before_noop(&mut self,book:&mut Install,history:&History,new_intent:&IntentData)->Result<()> {
        let result=(||{
            check(book.worker_stderr_is_gate && book.worker_go_eof && book.registration.verified
                && new_intent.recovery_data()==Some(&self.reference) && !self.settled && self.first.is_none(),
                "noop-recovery-original-go-required")?;
            self.post(book,history)?;
            let (receipt,raw)=self.receipt.as_ref().ok_or("noop-recovery-receipt-required")?;
            check(raw==&self.receipt_bytes && book.identity(*receipt)?.mode&0o7777==0o444,
                "noop-recovery-complete-receipt-required")?;
            let archive=data(transaction::archived_state_name_data(history.current.state.invocation_data()))?;
            if self.placement==NoopStatePlacementData::Swapped {
                let (pending,bytes)=self.pending.as_ref().ok_or("noop-recovery-pending-state")?;
                file_post(book,*pending,bytes)?;held_bytes(book,history.state_original,&history.state_bytes)?;
                check(book.originals[history.state_original].parent==Some(self.root)
                    && book.originals[history.state_original].name==archive
                    && book.originals[*pending].parent==Some(self.root)
                    && book.originals[*pending].name==transaction::STATE_NAME,"noop-recovery-state-swap-placement")?;
                book.clock()?;
                match native::swap_installation_state(book.fd(self.root)?.as_fd(),&archive) {
                    Ok(())=>self.returned=ReturnedData::KnownSuccess,
                    Err(_)=>{self.returned=ReturnedData::Unknown;book.unknown=true;return Err("noop-recovery-state-swap");},
                }
                rebind_renamed(book,history.state_original,self.root,transaction::STATE_NAME)?;
                rebind_renamed(book,*pending,self.root,&archive)?;
                book.persist(self.root,false)?;self.placement=NoopStatePlacementData::PendingBeforeSwap;
            }
            if let Some((pending,bytes))=self.pending.take() {
                let saved=data(self.reference.preserved_name_data(new_intent.invocation_data(),"state"))?;
                let result=self.move_file(book,pending,self.root,&archive,self.stage,&saved,&bytes);
                if let Err(why)=result {self.pending=Some((pending,bytes));return Err(why);}
                book.forward_close(pending,"noop-recovery-state-close")?;
            }
            for index in 0..self.attempts.len() {
                if !self.attempts[index].at_root {continue;}
                let id=self.attempts[index].intent.invocation_data().to_owned();
                let name=data(transaction::intent_name_data(&id))?;
                let (reader,raw)=metadata_original(book,self.root,&name,transaction::INTENT_LIMIT)?;
                check(raw==self.attempts[index].raw && original(book,reader)?==self.attempts[index].identity,
                    "noop-recovery-attempt-original")?;
                let saved=data(self.reference.preserved_name_data(&id,"intent"))?;
                self.move_file(book,reader,self.root,&name,self.stage,&saved,&raw)?;
                self.attempts[index].at_root=false;
                book.forward_close(reader,"noop-recovery-intent-close")?;
            }
            book.absent(self.root,&archive)?;self.post(book,history)?;
            check(book.originals[history.state_original].name==transaction::STATE_NAME,"noop-recovery-restored-state")?;
            self.settled=true;Ok(())
        })();
        result.map_err(|why|self.fail(why))
    }
}
// One closed namespace, authenticated by a recorded reference and original
// receipt, not by a permissive prefix. Names alone never enter the census.
fn preserved_role<'a>(reference:&RecoveryReferenceData,name:&'a str)->Result<Option<(&'a str,&'a str)>> {
    let prefix=format!(".noop-recovery-{}-",reference.torn_invocation_data());
    let Some(tail)=name.strip_prefix(&prefix) else{return Ok(None);};
    let (id,role)=tail.split_once('.').ok_or("noop-recovery-preserved-name")?;
    let role=role.strip_suffix(".json").ok_or("noop-recovery-preserved-name")?;
    check(data(reference.preserved_name_data(id,role))?==name,"noop-recovery-preserved-name")?;
    Ok(Some((id,role)))
}
pub(super) struct Census {
    pub(super) names:BTreeSet<String>,pub(super) invocations:BTreeSet<String>,
    pub(super) files:usize,pub(super) bytes:u64,facts:Vec<InstallInvocationFactData>,
}
fn add_extent(census:&mut Census,name:String,size:usize)->Result<()> {
    check(census.names.insert(name),"noop-recovery-duplicate-role")?;
    census.files=census.files.checked_add(1).ok_or("noop-recovery-census-bound")?;
    census.bytes=census.bytes.checked_add(size as u64).filter(|n|*n<=installation_record::PAYLOAD_LIMIT)
        .ok_or("noop-recovery-census-bound")?;Ok(())
}
// Completed-reference audit is shared by ordinary observation and removal.
// A preserved incomplete attempt is never added to the successful history.
pub(super) fn recorded_census(book:&mut Install,root:usize,stage:usize,reference:&RecoveryReferenceData,
    history:&History,selected:&ReleaseSetData)->Result<Census> {
    let roster=roster_now(book,stage)?;
    let mut declared=0usize;
    for name in roster.keys() {
        if preserved_role(reference,name)?.is_some_and(|(_,role)|role=="intent") {
            declared=declared.checked_add(1).ok_or("noop-recovery-attempt-bound")?;
        }
    }
    reserve(book,declared.max(1))?;
    let name=reference.receipt_name_data();
    let (reader,receipt_raw)=metadata_original(book,stage,&name,RECEIPT_LIMIT)?;
    check(hash(&receipt_raw)==reference.receipt_sha256_data(),"noop-recovery-receipt-digest")?;
    let (receipt,base)=parse_receipt(&receipt_raw,selected,history)?;
    check(receipt.stage_invocation==reference.stage_invocation_data()
        && base.invocation_data()==reference.torn_invocation_data()
        && receipt.root==original(book,root)? && receipt.stage==original(book,stage)?,"noop-recovery-receipt-originals")?;
    let (previous,previous_sha)=base.previous_state_data().ok_or("noop-recovery-prior-required")?;
    let old=recorded_previous(history,previous,previous_sha)?;
    let old_name=if history.current.state.invocation_data()==previous {transaction::STATE_NAME.to_owned()}
        else{data(transaction::archived_state_name_data(previous))?};
    let (old_reader,old_raw)=metadata_original(book,root,&old_name,transaction::STATE_LIMIT)?;
    check(hash(&old_raw)==old.state.digest_data() && original(book,old_reader)?==receipt.old_state,
        "noop-recovery-old-original")?;
    held_bytes(book,old_reader,&old_raw)?;book.forward_close(old_reader,"noop-recovery-old-close")?;
    let mut census=Census{names:BTreeSet::new(),invocations:BTreeSet::new(),files:0,bytes:0,facts:Vec::new()};
    add_extent(&mut census,name,receipt_raw.len())?;
    let mut attempts:BTreeMap<String,(IntentData,Vec<u8>)>=BTreeMap::new();
    let mut requests=BTreeSet::new();
    for name in roster.keys() {
        let Some((id,role))=preserved_role(reference,name)? else{continue;};
        if role!="intent"{continue;}
        check(attempts.len()<transaction::INVOCATION_LIMIT&&!known(history,id),"noop-recovery-history-adoption")?;
        let raw=metadata_bytes(book,stage,name,transaction::INTENT_LIMIT)?;
        let intent=data(IntentData::parse_recorded_data(&raw,selected))?;
        let derived=data(NoopRecoveryData::from_recorded_data(&intent,(&old.state,&old.capsule),selected))?;
        check(intent.invocation_data()==id && derived.stage_invocation_data()==reference.stage_invocation_data()
            && requests.insert(intent.request_id_data().to_owned())
            && (if id==base.invocation_data(){raw==receipt.torn_intent.as_bytes()&&intent.recovery_data().is_none()}
                else{intent.recovery_data()==Some(reference)}),"noop-recovery-preserved-intent")?;
        add_extent(&mut census,name.clone(),raw.len())?;census.invocations.insert(id.to_owned());census.facts.push(InstallInvocationFactData::intent(&intent)?);
        attempts.insert(id.to_owned(),(intent,raw));
    }
    check(attempts.contains_key(base.invocation_data()),"noop-recovery-base-not-preserved")?;
    check(history.originals.len().checked_add(1).and_then(|n|n.checked_add(attempts.len()))
        .is_some_and(|n|n<=transaction::INVOCATION_LIMIT),"noop-recovery-aggregate-attempts")?;
    for name in roster.keys() {
        let Some((id,role))=preserved_role(reference,name)? else{continue;};
        if role=="intent"{continue;}
        let preserving=if let Some((intent,_))=attempts.get(id){intent}
            else if id==history.current.intent.invocation_data(){&history.current.intent}
            else{&history.originals.get(id).ok_or("noop-recovery-preserver-missing")?.intent};
        check(preserving.recovery_data()==Some(reference)
            && preserving.previous_state_data()==Some((old.state.invocation_data(),old.state.digest_data())),
            "noop-recovery-preserver-binding")?;
        let limit=if role=="state"{transaction::STATE_LIMIT}else{RECEIPT_LIMIT};
        let (file,raw)=optional_file(book,stage,name,limit,true)?.ok_or("noop-recovery-preserved-file")?;
        let sealed=book.identity(file)?.mode&0o7777==0o444;
        if role=="receipt-prefix" {
            check(!sealed && receipt_raw.starts_with(&raw),"noop-recovery-preserved-receipt-prefix")?;
        }else{
            let matches=attempts.values().any(|(intent,_)|
                NoopRecoveryData::from_recorded_data(intent,(&old.state,&old.capsule),selected)
                    .is_ok_and(|derived|if sealed {derived.expected_state_data()==raw}
                        else {derived.expected_state_data().starts_with(&raw)}));
            check(matches,"noop-recovery-preserved-state-prefix")?;
        }
        removal_snapshot_metadata_kind(book,file,&raw,5)?;
        file_post(book,file,&raw)?;book.forward_close(file,"noop-recovery-preserved-close")?;
        add_extent(&mut census,name.clone(),raw.len())?;
    }
    held_bytes(book,reader,&receipt_raw)?;book.forward_close(reader,"noop-recovery-census-receipt-close")?;
    book.check_name(stage,false)?;Ok(census)
}

impl Observation {
    // The pending namespace is authenticated from the captured original Intent
    // set and the new immutable Intent, never just a filename prefix. This is
    // used before GO and again after the actual worker has preserved originals.
    fn pending_census(&self,book:&mut Install,history:&History,selected:&ReleaseSetData,
        current:Option<&IntentData>,completed:bool)->Result<Census> {
        reserve(book,self.attempts.len())?;
        self.post(book,history)?;
        let mut census=Census{names:BTreeSet::new(),invocations:BTreeSet::new(),files:0,bytes:0,facts:Vec::new()};
        let roster=roster_now(book,self.stage)?;
        if let Some((reader,raw))=&self.receipt {
            file_post(book,*reader,raw)?;
            add_extent(&mut census,self.reference.receipt_name_data(),raw.len())?;
        }else{book.absent(self.stage,&self.reference.receipt_name_data())?;}
        let mut requests=BTreeSet::new();
        for attempt in &self.attempts {
            check(requests.insert(attempt.intent.request_id_data()),"noop-recovery-request-reused")?;
            census.invocations.insert(attempt.intent.invocation_data().into());
            census.facts.push(InstallInvocationFactData::intent(&attempt.intent)?);
            let stage_name=data(self.reference.preserved_name_data(attempt.intent.invocation_data(),"intent"))?;
            let root_name=data(transaction::intent_name_data(attempt.intent.invocation_data()))?;
            let at_root=attempt.at_root&&!completed;
            let (parent,name,absent_parent,absent_name)=if at_root {
                (self.root,root_name.as_str(),self.stage,stage_name.as_str())
            }else{(self.stage,stage_name.as_str(),self.root,root_name.as_str())};
            book.absent(absent_parent,absent_name)?;
            let (reader,raw)=metadata_original(book,parent,name,transaction::INTENT_LIMIT)?;
            check(raw==attempt.raw && original(book,reader)?==attempt.identity,"noop-recovery-intent-original-post")?;
            held_bytes(book,reader,&raw)?;book.forward_close(reader,"noop-recovery-intent-post-close")?;
            if !at_root {add_extent(&mut census,stage_name,raw.len())?;}
        }
        if let Some(current)=current {
            check(current.recovery_data()==Some(&self.reference)
                && !census.invocations.contains(current.invocation_data())
                && requests.insert(current.request_id_data()),"noop-recovery-current-preserver")?;
            let _=data(NoopRecoveryData::from_recorded_data(current,(&history.current.state,&history.current.capsule),selected))?;
        }
        for name in roster.keys() {
            let Some((id,role))=preserved_role(&self.reference,name)? else{continue;};
            if role=="intent" {
                check(census.names.contains(name),"noop-recovery-foreign-preserved-intent")?;continue;
            }
            let preserving=self.attempts.iter().find(|a|a.intent.invocation_data()==id).map(|a|&a.intent)
                .or_else(||current.filter(|i|i.invocation_data()==id)).ok_or("noop-recovery-preserver-missing")?;
            check(preserving.recovery_data()==Some(&self.reference)
                && preserving.previous_state_data()==Some((history.current.state.invocation_data(),history.current.state.digest_data())),
                "noop-recovery-preserver-binding")?;
            let limit=if role=="state"{transaction::STATE_LIMIT}else{RECEIPT_LIMIT};
            let (reader,raw)=optional_file(book,self.stage,name,limit,true)?.ok_or("noop-recovery-preserved-file")?;
            let sealed=book.identity(reader)?.mode&0o7777==0o444;
            let matching=if role=="receipt-prefix" {!sealed&&self.receipt_bytes.starts_with(&raw)}else{
                self.attempts.iter().any(|a|NoopRecoveryData::from_recorded_data(&a.intent,
                    (&history.current.state,&history.current.capsule),selected).is_ok_and(|derived|
                    if sealed{derived.expected_state_data()==raw}else{derived.expected_state_data().starts_with(&raw)}))
            };
            check(matching,"noop-recovery-preserved-prefix")?;
            file_post(book,reader,&raw)?;book.forward_close(reader,"noop-recovery-preserved-post-close")?;
            add_extent(&mut census,name.clone(),raw.len())?;
        }
        self.post(book,history)?;Ok(census)
    }
    pub(super) fn root_names(&self,names:&mut BTreeSet<String>,evidence:&mut u64)->Result<()> {
        for attempt in &self.attempts {
            if attempt.at_root {
                check(names.insert(data(transaction::intent_name_data(attempt.intent.invocation_data()))?),"noop-recovery-root-duplicate")?;
                *evidence=evidence.checked_add(attempt.raw.len() as u64).ok_or("noop-recovery-storage")?;
            }
        }
        if self.pending.is_some() {
            let old=self.base.previous_state_data().ok_or("noop-recovery-prior-required")?.0;
            check(names.insert(data(transaction::archived_state_name_data(old))?),"noop-recovery-root-duplicate")?;
            *evidence=evidence.checked_add(self.pending.as_ref().ok_or("noop-recovery-pending")?.1.len() as u64)
                .ok_or("noop-recovery-storage")?;
        }Ok(())
    }
    pub(super) fn binding(&self)->serde_json::Value {
        serde_json::json!({"reference":self.reference,"root":self.receipt_data.root,"stage":self.receipt_data.stage,
            "oldState":self.old_state,"receiptSha256":hash(&self.receipt_bytes),
            "attempts":self.attempts.iter().map(|a|serde_json::json!({"invocation":a.intent.invocation_data(),
                "sha256":hash(&a.raw),"original":a.identity,"atRoot":a.at_root})).collect::<Vec<_>>(),
            "pendingSha256":self.pending.as_ref().map(|(_,body)|hash(body))})
    }
    pub(super) fn ready(&self,book:&Install,history:&History)->Result<()> {
        self.post(book,history)?;
        let (reader,raw)=self.receipt.as_ref().ok_or("noop-recovery-receipt-required")?;
        check(raw==&self.receipt_bytes && book.identity(*reader)?.mode&0o7777==0o444 && self.first.is_none(),
            "noop-recovery-receipt-required")
    }
    pub(super) fn after_join(&self,book:&mut Install,history:&History,selected:&ReleaseSetData,intent:&IntentData)->Result<()> {
        self.ready(book,history)?;
        if let Some((pending,body))=&self.pending {
            let saved=data(self.reference.preserved_name_data(intent.invocation_data(),"state"))?;
            // The parent retained this exact file before GO. Do not substitute
            // a newly discovered equal-content prefix for that original.
            rebind_renamed(book,*pending,self.stage,&saved)?;file_post(book,*pending,body)?;
        }
        let recovery=namespace(book,self.root,history,selected,Some(self),Some(intent),true)?;
        let instance=self.reference.stage_invocation_data();
        let holder=history.originals.values().chain(std::iter::once(&history.current))
            .find(|r|r.intent.invocation_data()==instance&&r.intent.action_data()!=ActionData::SamePackageNoop)
            .ok_or("noop-recovery-generation-stage")?;
        let mut bytes=0;
        stage_roster_selected(book,self.root,&holder.intent,&mut bytes,None,Some(history),Some(&recovery))?;
        let mut wanted=self.root_names.clone();
        for attempt in &self.attempts {wanted.remove(&data(transaction::intent_name_data(attempt.intent.invocation_data()))?);}
        wanted.insert(data(transaction::intent_name_data(intent.invocation_data()))?);
        wanted.insert(data(transaction::archived_state_name_data(history.current.state.invocation_data()))?);
        if book.registration.verified{wanted.insert(paths::REGISTRATION_GATE_NAME.into());}
        exact_roster(book,self.root,&wanted)?;self.post(book,history)
    }
    pub(super) fn planned_receipt_bytes(&self)->u64 {RECEIPT_LIMIT as u64}
    pub(super) fn complete(&self)->bool {self.settled&&self.first.is_none()&&self.returned!=ReturnedData::Unknown}
}

// All receipt groups share one invocation allowance; each archive cannot renew
// that allowance. Stage callers receive only names from actual closed audits.
pub(super) struct Namespace {
    pub(super) stages:BTreeMap<String,BTreeSet<String>>,pub(super) bytes:u64,pub(super) attempts:usize,
    pub(super) facts:InstallInvocationSetData,
}
pub(super) fn namespace(book:&mut Install,root:usize,history:&History,selected:&ReleaseSetData,
    pending:Option<&Observation>,current:Option<&IntentData>,completed:bool)->Result<Namespace> {
    if pending.is_none()&&!history.originals.values().chain(std::iter::once(&history.current))
        .any(|record|record.intent.recovery_data().is_some()) {
        return Ok(Namespace{stages:BTreeMap::new(),bytes:0,attempts:0,facts:InstallInvocationSetData::empty()});
    }
    // Bound the shared small maps/identity facts before allocating them. Each
    // referenced group separately reserves its actual original/read backing.
    reserve(book,1)?;
    let mut refs:BTreeMap<String,RecoveryReferenceData>=BTreeMap::new();
    for record in history.originals.values().chain(std::iter::once(&history.current)) {
        if let Some(reference)=record.intent.recovery_data() {
            let key=reference.receipt_name_data();
            check(refs.get(&key).is_none_or(|old|old==reference),"noop-recovery-reference-collision")?;
            refs.insert(key,reference.clone());
        }
    }
    let mut ids:BTreeSet<String>=history.originals.keys().cloned().collect();
    ids.insert(history.current.state.invocation_data().into());
    if let Some(current)=current{check(ids.insert(current.invocation_data().into()),"noop-recovery-invocation-reused")?;}
    let complete_count=ids.len();
    let mut facts=InstallInvocationSetData::empty();
    for record in history.originals.values().chain(std::iter::once(&history.current)) {
        check(facts.insert(InstallInvocationFactData::intent(&record.intent)?)?,"noop-recovery-invocation-reused")?;
    }
    if let Some(current)=current{check(facts.insert(InstallInvocationFactData::intent(current)?)?,"noop-recovery-invocation-reused")?;}
    let mut out=Namespace{stages:BTreeMap::new(),bytes:0,attempts:0,facts:InstallInvocationSetData::empty()};
    let mut add=|reference:&RecoveryReferenceData,census:Census|->Result<()> {
        for id in census.invocations {check(ids.insert(id),"noop-recovery-cross-group-invocation")?;}
        for fact in census.facts {check(facts.insert(fact)?,"noop-recovery-cross-group-invocation")?;}
        check(ids.len()<=transaction::INVOCATION_LIMIT,"noop-recovery-aggregate-invocations")?;
        let names=out.stages.entry(reference.stage_invocation_data().to_owned()).or_default();
        for name in census.names {check(names.insert(name),"noop-recovery-cross-group-role")?;}
        out.bytes=out.bytes.checked_add(census.bytes).filter(|n|*n<=installation_record::PAYLOAD_LIMIT)
            .ok_or("noop-recovery-storage")?;Ok(())
    };
    for reference in refs.values() {
        check(pending.is_none_or(|p|p.reference.receipt_name_data()!=reference.receipt_name_data()),"noop-recovery-recorded-pending-collision")?;
        let stage=book.open(Some(root),&format!(".install-{}",reference.stage_invocation_data()),true)?;
        book.protected(stage,true,Some(0o700))?;
        let census=recorded_census(book,root,stage,reference,history,selected)?;
        book.forward_close(stage,"noop-recovery-stage-census-close")?;add(reference,census)?;
    }
    if let Some(pending)=pending {add(&pending.reference,pending.pending_census(book,history,selected,current,completed)?)?;}
    out.attempts=ids.len().checked_sub(complete_count).ok_or("noop-recovery-invocation-count")?;
    out.facts=facts;
    Ok(out)
}

// Transport grammar only. Content authority still requires the complete
// receipt/reference audit; this predicate never admits an arbitrary prefix.
pub(crate) fn snapshot_prefix_path(path:&str)->Option<&str> {
    let (stage,leaf)=path.split_once('/')?;
    let instance=stage.strip_prefix(".install-")?;
    if !worker::invocation_valid(instance)||leaf.contains('/') {return None;}
    let tail=leaf.strip_prefix(".noop-recovery-")?;
    let (torn,tail)=tail.split_once('-')?;let (preserver,role)=tail.split_once('.')?;
    let role=role.strip_suffix(".json")?;
    (worker::invocation_valid(torn)&&worker::invocation_valid(preserver)
        && matches!(role,"state"|"receipt-prefix")).then_some(role)
}
pub(crate) fn snapshot_prefix_shape(path:&str,id:Identity,flags:u32,size:u64)->bool {
    let Some(role)=snapshot_prefix_path(path)else{return false;};
    id.uid==0&&id.gid==0&&id.links==1&&flags==0&&id.size>=0&&id.size as u64==size
        && match role {
            "state"=>size<=transaction::STATE_LIMIT as u64
                && (id.mode==0o100600||id.mode==0o100444&&size>0),
            "receipt-prefix"=>id.mode==0o100600&&size<=RECEIPT_LIMIT as u64,
            _=>false,
        }
}

pub(super) struct SnapshotCensus {pub(super) indices:Vec<usize>,pub(super) attempts:Vec<InstallInvocationFactData>}
fn snapshot_span<'a>(genesis:&'a RemovalGenesisData,path:&str)->Result<(usize,&'a RemovalControlSpanData)> {
    genesis.controls_data().iter().enumerate().find(|(_,r)|r.path_data()==path&&matches!(r.kind_data(),0|5))
        .ok_or("noop-recovery-snapshot-span")
}
fn snapshot_bytes<F:FnMut(u64,&mut[u8])->Result<usize>>(genesis:&RemovalGenesisData,path:&str,
    limit:usize,read:&mut F)->Result<Vec<u8>> {
    let (_,span)=snapshot_span(genesis,path)?;
    if span.kind_data()==0 {return rehome_span_bytes_data(genesis,path,limit,read);}
    check(snapshot_prefix_shape(path,span.identity_data(),span.flags_data(),span.len_data())
        && span.len_data()<=limit as u64,"noop-recovery-snapshot-prefix")?;
    let size=span.len_data() as usize;let mut raw=Vec::new();
    raw.try_reserve_exact(size).map_err(|_|"noop-recovery-snapshot-memory")?;
    check(raw.capacity()<=limit,"noop-recovery-snapshot-memory")?;raw.resize(size,0);
    let mut at=0;while at<size {
        let n=read(span.offset_data().checked_add(at as u64).ok_or("noop-recovery-snapshot-offset")?,&mut raw[at..])?;
        check(n>0&&n<=size-at,"noop-recovery-snapshot-short-read")?;at+=n;
    }
    check(<[u8;32]>::from(Sha256::digest(&raw))==*span.digest_data(),"noop-recovery-snapshot-hash")?;Ok(raw)
}
fn snapshot_memory(base:usize,size:usize,available:usize)->Result<()> {
    check(size.checked_mul(8).and_then(|n|n.checked_add(base)).is_some_and(|n|n<=available),
        "noop-recovery-snapshot-memory")
}
// The immutable removal snapshot carries the exact already-observed originals.
// This reader still binds each extra span to complete State evidence and one
// closed recovery receipt; it does not accept a renamed role by its prefix.
pub(super) fn snapshot_census<F:FnMut(u64,&mut[u8])->Result<usize>>(genesis:&RemovalGenesisData,
    reference:&RecoveryReferenceData,selected:&ReleaseSetData,state:&StateData,available:usize,
    read:&mut F)->Result<SnapshotCensus> {
    let top=format!(".install-{}",reference.stage_invocation_data());
    let receipt_path=rehome_path_data(&[&top,&reference.receipt_name_data()])?;
    let (receipt_index,receipt_span)=snapshot_span(genesis,&receipt_path)?;
    snapshot_memory(0,receipt_span.len_data() as usize,available)?;
    let receipt_raw=snapshot_bytes(genesis,&receipt_path,RECEIPT_LIMIT,read)?;
    check(hash(&receipt_raw)==reference.receipt_sha256_data(),"noop-recovery-snapshot-receipt")?;
    let value=mobile_release_desktop::protocol::strict_json(&receipt_raw).map_err(|_|"noop-recovery-receipt-shape")?;
    let receipt:Receipt=serde_json::from_value(value).map_err(|_|"noop-recovery-receipt-shape")?;
    let mut canonical=serde_json::to_vec(&receipt).map_err(|_|"noop-recovery-receipt-shape")?;canonical.push(b'\n');
    check(canonical==receipt_raw,"noop-recovery-receipt-canonical")?;drop(canonical);
    let base=data(IntentData::parse_recorded_data(receipt.torn_intent.as_bytes(),selected))?;
    let (previous,sha)=base.previous_state_data().ok_or("noop-recovery-prior-required")?;
    let evidence=state.evidence_data().find(|e|e.invocation==previous).ok_or("noop-recovery-snapshot-history")?;
    check(evidence.state_sha256==sha&&evidence.state_sha256==receipt.previous_state_sha256
        && evidence.capsule_sha256==receipt.previous_capsule_sha256,"noop-recovery-snapshot-old-digests")?;
    let old_path=data(transaction::archived_state_name_data(previous))?;
    let (_,old_span)=snapshot_span(genesis,&old_path)?;
    let cap_path=data(transaction::capsule_name_data(previous))?;
    let (_,cap_span)=snapshot_span(genesis,&cap_path)?;
    let retained=(receipt_span.len_data() as usize).checked_add(old_span.len_data() as usize)
        .and_then(|n|n.checked_add(cap_span.len_data() as usize)).and_then(|n|n.checked_mul(8))
        .and_then(|n|n.checked_add(4*transaction::INVOCATION_LIMIT*std::mem::size_of::<usize>()
            +transaction::INVOCATION_LIMIT*std::mem::size_of::<InstallInvocationFactData>()))
        .ok_or("noop-recovery-snapshot-memory")?;
    snapshot_memory(retained,0,available)?;
    let old_raw=snapshot_bytes(genesis,&old_path,transaction::STATE_LIMIT,read)?;
    let old=data(StateData::parse_data(&old_raw,selected))?;drop(old_raw);
    let cap_raw=snapshot_bytes(genesis,&cap_path,transaction::CAPSULE_LIMIT,read)?;
    let cap=data(CapsuleData::parse_recorded_data(&cap_raw,selected))?;drop(cap_raw);
    let derived=data(NoopRecoveryData::from_recorded_data(&base,(&old,&cap),selected))?;
    let root=genesis.directories_data().iter().find(|d|d.path_data().is_empty()).ok_or("noop-recovery-snapshot-root")?.identity_data();
    let stage=genesis.directories_data().iter().find(|d|d.path_data()==top).ok_or("noop-recovery-snapshot-stage")?.identity_data();
    check(receipt.schema_version==1&&receipt.kind=="mrk-noop-original-preservation-v1"
        && receipt.target==selected.target_data().target()&&receipt.stage_invocation==reference.stage_invocation_data()
        && base.invocation_data()==reference.torn_invocation_data()&&base.recovery_data().is_none()
        && derived.stage_invocation_data()==reference.stage_invocation_data()
        && old.digest_data()==receipt.previous_state_sha256&&cap.digest_data()==receipt.previous_capsule_sha256
        && [receipt.root,receipt.stage,receipt.old_state].into_iter().all(|v|v.valid_data())
        && (receipt.root.device,receipt.root.inode)==(i64::from(root.dev),root.ino)
        && (receipt.stage.device,receipt.stage.inode)==(i64::from(stage.dev),stage.ino)
        && (receipt.old_state.device,receipt.old_state.inode)==(i64::from(old_span.identity_data().dev),old_span.identity_data().ino),
        "noop-recovery-snapshot-originals")?;
    let mut indices=Vec::new();let mut attempts=Vec::new();
    indices.try_reserve_exact(4*transaction::INVOCATION_LIMIT).map_err(|_|"noop-recovery-snapshot-memory")?;
    attempts.try_reserve_exact(transaction::INVOCATION_LIMIT).map_err(|_|"noop-recovery-snapshot-memory")?;
    indices.push(receipt_index);
    for (index,span) in genesis.controls_data().iter().enumerate() {
        let Some((parent,leaf))=span.path_data().split_once('/') else{continue;};if parent!=top{continue;}
        let Some((id,role))=preserved_role(reference,leaf)?else{continue;};
        if role!="intent"{continue;}
        check(span.kind_data()==0&&id!=state.invocation_data()&&!state.evidence_data().any(|e|e.invocation==id)
            && attempts.len()<transaction::INVOCATION_LIMIT,"noop-recovery-snapshot-intent")?;
        snapshot_memory(retained,span.len_data() as usize,available)?;
        let raw=snapshot_bytes(genesis,span.path_data(),transaction::INTENT_LIMIT,read)?;
        let intent=data(IntentData::parse_recorded_data(&raw,selected))?;
        check(intent.invocation_data()==id&&(if id==base.invocation_data(){raw==receipt.torn_intent.as_bytes()}
            else{intent.recovery_data()==Some(reference)}),"noop-recovery-snapshot-attempt-binding")?;
        let _=data(NoopRecoveryData::from_recorded_data(&intent,(&old,&cap),selected))?;
        let fact=InstallInvocationFactData::intent(&intent)?;
        check(!attempts.contains(&fact),"noop-recovery-snapshot-duplicate-attempt")?;
        attempts.push(fact);indices.push(index);
    }
    let base_path=rehome_path_data(&[&top,&data(reference.preserved_name_data(base.invocation_data(),"intent"))?])?;
    check(indices.iter().any(|i|genesis.controls_data()[*i].path_data()==base_path),"noop-recovery-snapshot-base")?;
    for (index,span) in genesis.controls_data().iter().enumerate() {
        let Some((parent,leaf))=span.path_data().split_once('/') else{continue;};if parent!=top{continue;}
        let Some((id,role))=preserved_role(reference,leaf)?else{continue;};if role=="intent"{continue;}
        check(span.kind_data()==5&&snapshot_prefix_shape(span.path_data(),span.identity_data(),span.flags_data(),span.len_data()),
            "noop-recovery-snapshot-prefix-kind")?;
        let preserving_path=if id==state.invocation_data()||state.evidence_data().any(|e|e.invocation==id){data(transaction::intent_name_data(id))?}
            else{rehome_path_data(&[&top,&data(reference.preserved_name_data(id,"intent"))?])?};
        let (_,preserving_span)=snapshot_span(genesis,&preserving_path)?;
        snapshot_memory(retained,span.len_data().checked_add(preserving_span.len_data()).ok_or("noop-recovery-snapshot-memory")? as usize,available)?;
        let raw=snapshot_bytes(genesis,&preserving_path,transaction::INTENT_LIMIT,read)?;
        let preserver=data(IntentData::parse_recorded_data(&raw,selected))?;drop(raw);
        check(preserver.invocation_data()==id&&preserver.recovery_data()==Some(reference)
            && preserver.previous_state_data()==base.previous_state_data(),"noop-recovery-snapshot-preserver")?;
        let body=snapshot_bytes(genesis,span.path_data(),if role=="state"{transaction::STATE_LIMIT}else{RECEIPT_LIMIT},read)?;
        let mut matching=role=="receipt-prefix"&&receipt_raw.starts_with(&body);
        if role=="state" {
            for candidate in &indices {
                let row=&genesis.controls_data()[*candidate];
                if !row.path_data().ends_with(".intent.json"){continue;}
                snapshot_memory(retained,body.len().checked_add(row.len_data() as usize).ok_or("noop-recovery-snapshot-memory")?,available)?;
                let raw=snapshot_bytes(genesis,row.path_data(),transaction::INTENT_LIMIT,read)?;
                let intent=data(IntentData::parse_recorded_data(&raw,selected))?;
                let derived=data(NoopRecoveryData::from_recorded_data(&intent,(&old,&cap),selected))?;
                if if span.identity_data().mode==0o100444 {derived.expected_state_data()==body}
                    else{derived.expected_state_data().starts_with(&body)} {matching=true;break;}
            }
        }
        check(matching,"noop-recovery-snapshot-prefix-binding")?;
        check(indices.len()<4*transaction::INVOCATION_LIMIT,"noop-recovery-snapshot-control-count")?;indices.push(index);
    }
    Ok(SnapshotCensus{indices,attempts})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(mode:u32,size:i64)->Identity {Identity{dev:1,ino:9,mode,uid:0,gid:0,links:1,size,
        mtime:1,mtime_ns:0,ctime:1,ctime_ns:0}}
    #[test]
    fn preserved_prefix_transport_is_closed_without_relaxing_ordinary_controls() {
        let path=format!(".install-{}/.noop-recovery-{}-{}.state.json","a".repeat(32),"b".repeat(32),"c".repeat(32));
        let (seed,header)=removal_archive_test_snapshot(false,0);
        for (suffix,mode,body) in [("state",0o100600,b"".as_slice()),("state",0o100600,b"part".as_slice()),
            ("state",0o100444,b"complete".as_slice()),("receipt-prefix",0o100600,b"".as_slice())] {
            let path=path.replace(".state.json",&format!(".{suffix}.json"));
            let row=RemovalSnapshotControl{path:path.clone(),identity:file(mode,body.len() as i64),flags:0,
                size:body.len() as u64,digest:Sha256::digest(body).into(),kind:5,held:None};
            assert!(snapshot_prefix_shape(&path,row.identity,0,row.size));
            let frame=removal_snapshot_frame_data(&row).unwrap();let mut raw=seed[..header].to_vec();
            raw.extend(frame);raw.extend(body);
            assert!(removal_archive_test_parse(&raw,true).unwrap().0,"{suffix}/{mode:o}");
            let mut bad=raw.clone();bad[header]=0;
            if mode==0o100600||body.is_empty(){assert!(removal_archive_test_parse(&bad,true).is_err());}
            else{assert!(removal_archive_test_parse(&bad,true).unwrap().0);} // old kind0 grammar unchanged; semantic rehome rejects misclassified prefixes.
            let mut bad=raw;bad[header]=6;assert!(removal_archive_test_parse(&bad,true).is_err());
        }
        for (path,mode,size,flags) in [
            ("ordinary.json".to_owned(),0o100600,0,0),
            (path.replace(".state.json",".intent.json"),0o100600,0,0),
            (path.replace(".state.json",".receipt-prefix.json"),0o100444,1,0),
            (path.replace(".state.json",".state.json/child"),0o100600,0,0),
            (path.replace(&"a".repeat(32),&"A".repeat(32)),0o100600,0,0),
            (path.clone(),0o100555,1,0),(path.clone(),0o100444,0,0),
            (path.clone(),0o100600,transaction::STATE_LIMIT as i64+1,0),(path.clone(),0o100600,1,1)] {
            assert!(!snapshot_prefix_shape(&path,file(mode,size),flags,size as u64),"{path}/{mode:o}/{size}");
        }
        assert!(quote_data(0).is_err());assert!(quote_data(transaction::INVOCATION_LIMIT+1).is_err());
        assert!(quote_data(transaction::INVOCATION_LIMIT).unwrap().0<installation_record::CONTROL_LIMIT as u64);
    }
    fn writer(writes:u64)->transaction::WriterObservationData {transaction::WriterObservationData{
        returned:true,exit_code:Some(0),original_joined:true,result_eof:true,original_closes_known:true,
        within_original_deadline:true,payload_write_count:writes,payload_write_bytes:writes}}
    fn recovery_snapshot(prefix:usize)->(RemovalGenesisData,ReleaseSetData,StateData,RecoveryReferenceData,Vec<u8>) {
        use mobile_release_desktop::macos_remove_protocol::{BindingData,BindingInputData,TargetData};
        let (seed,selected,_,old_intent,seed_raw)=rehome_test_fixture_with_raw();
        let old_id=old_intent.invocation_data();let generation=GenerationData::from_original_fields_data(&selected,
            selected.current_data(),old_id,installation_record::DirectoryIdentity{device:1,inode:90,mode:0o040755,uid:0,gid:0,flags:0},
            AppIdentityData::from_original_fields_data(1,91,0o040555,0,0,0).unwrap()).unwrap();
        let old_raw=StateData::encode_applied_data(&old_intent,None,&generation,&selected).unwrap();
        let old=StateData::parse_data(&old_raw,&selected).unwrap();
        let old_cap_raw=CapsuleData::encode_data(&old_intent,None,Some(&old),Some(selected.current_data()),
            transaction::RecordedOutcomeData::Applied,writer(1),&selected).unwrap();
        let old_cap=CapsuleData::parse_data(&old_cap_raw,&selected).unwrap();
        let torn_raw=IntentData::encode_data(&"e".repeat(32),&"f".repeat(32),ActionData::SamePackageNoop,
            Some((&old,&old_cap)),&selected).unwrap();
        let torn=IntentData::parse_data(&torn_raw,&selected).unwrap();
        let original=|inode|OriginalIdentityData{device:1,inode,birth_seconds:1,birth_nanoseconds:0};
        let receipt=Receipt{schema_version:1,kind:"mrk-noop-original-preservation-v1".into(),target:selected.target_data().target().into(),
            stage_invocation:old_id.into(),torn_intent:String::from_utf8(torn_raw.clone()).unwrap(),
            previous_state_sha256:old.digest_data().into(),previous_capsule_sha256:old_cap.digest_data().into(),
            root:original(40),stage:original(70),old_state:original(1001)};
        let mut receipt_raw=serde_json::to_vec(&receipt).unwrap();receipt_raw.push(b'\n');
        let reference=RecoveryReferenceData::new_data(old_id,torn.invocation_data(),&hash(&receipt_raw)).unwrap();
        let new_raw=IntentData::encode_with_recovery_data(&"3".repeat(32),&"4".repeat(32),ActionData::SamePackageNoop,
            Some((&old,&old_cap)),Some(&reference),&selected).unwrap();
        let new=IntentData::parse_data(&new_raw,&selected).unwrap();
        let state_raw=StateData::encode_applied_data(&new,Some((&old,&old_cap)),&generation,&selected).unwrap();
        let state=StateData::parse_data(&state_raw,&selected).unwrap();
        let cap_raw=CapsuleData::encode_data(&new,Some((&old,&old_cap)),Some(&state),Some(selected.current_data()),
            transaction::RecordedOutcomeData::SamePackage,writer(0),&selected).unwrap();
        let top=format!(".install-{old_id}");
        let mut body:Vec<(String,u8,Vec<u8>,u32,u64)>=seed.controls_data().iter().filter(|span|
            span.path_data()!=transaction::STATE_NAME&&span.path_data()!=transaction::capsule_name_data(old_id).unwrap())
            .map(|span|(span.path_data().into(),span.kind_data(),seed_raw[span.offset_data() as usize..
                (span.offset_data()+span.len_data()) as usize].to_vec(),0o100444,0)).collect();
        body.extend([
            (transaction::archived_state_name_data(old_id).unwrap(),0,old_raw,0o100444,1001),
            (transaction::capsule_name_data(old_id).unwrap(),0,old_cap_raw,0o100444,0),
            (transaction::intent_name_data(new.invocation_data()).unwrap(),0,new_raw,0o100444,0),
            (transaction::capsule_name_data(new.invocation_data()).unwrap(),0,cap_raw,0o100444,0),
            (transaction::STATE_NAME.into(),0,state_raw,0o100444,0),
            (format!("{top}/{}",reference.receipt_name_data()),0,receipt_raw,0o100444,0),
            (format!("{top}/{}",reference.preserved_name_data(torn.invocation_data(),"intent").unwrap()),0,torn_raw,0o100444,0),
        ]);
        let expected=NoopRecoveryData::from_recorded_data(&torn,(&old,&old_cap),&selected).unwrap();
        let length=prefix.min(expected.expected_state_data().len());
        body.push((format!("{top}/{}",reference.preserved_name_data(new.invocation_data(),"state").unwrap()),5,
            expected.expected_state_data()[..length].to_vec(),0o100600,0));
        body.push((format!("{top}/{}",reference.preserved_name_data(new.invocation_data(),"receipt-prefix").unwrap()),5,
            Vec::new(),0o100600,0));
        body.sort_by(|a,b|a.0.cmp(&b.0));
        let identity=Identity{dev:1,ino:40,mode:0o040755,uid:0,gid:0,links:2,size:64,mtime:1,mtime_ns:0,ctime:1,ctime_ns:0};
        let controls:Vec<_>=body.iter().enumerate().map(|(index,(path,kind,raw,mode,ino))|RemovalSnapshotControl{
            path:path.clone(),kind:*kind,identity:Identity{ino:if *ino==0{100+index as u64}else{*ino},mode:*mode,links:1,size:raw.len() as i64,..identity},
            flags:0,size:raw.len() as u64,digest:Sha256::digest(raw).into(),held:None}).collect();
        let directories=seed.directories_data().iter().map(|d|{
            let path=d.path_data();let mut children:Vec<_>=controls.iter().filter_map(|r|{
                if let Some((parent,leaf))=r.path.rsplit_once('/') {(parent==path).then_some((leaf.into(),r.identity.ino))}
                else{path.is_empty().then_some((r.path.clone(),r.identity.ino))}
            }).collect();
            for original in seed.directories_data() {
                if original.path_data().is_empty(){continue;}
                let parent=original.path_data().rsplit_once('/').map_or("",|(parent,_)|parent);
                if parent==path {children.push((original.path_data().rsplit('/').next().unwrap().into(),original.identity_data().ino));}
            }
            if path.is_empty(){children.push((paths::APP_NAME.into(),91));}
            children.sort_by(|a,b|a.0.cmp(&b.0));
            RemovalSnapshotDirectory{path:path.into(),identity:d.identity_data(),flags:0,children}
        }).collect();
        let mut capture=RemovalSnapshotCapture{root:0,versions:None,prior_archives:None,controls,directories,
            complete:false,quote:Some((0,0)),failed:false};capture.finish(RemovalArchiveCensus::empty(0).unwrap()).unwrap();
        let binding=selected.current_data().binding_data();
        let request=BindingData::new_data(BindingInputData{request_id:&"1".repeat(32),root_nonce:&"2".repeat(32),
            source_commit:binding.source_commit,release:binding.release,target:TargetData::Arm64,
            remove_producer_sha256:&seed.header.values[6],installed_producer_sha256:&seed.header.values[4],
            installed_inventory_sha256:binding.inventory_sha256,protocol_sha256:binding.protocol_sha256,
            start:10,work:110_000_000_010,hard:120_000_000_010}).unwrap();
        let mut raw=capture.header(&request,state.digest_data(),&selected.encode_data().unwrap(),0).unwrap();
        for (row,(_,_,bytes,_,_)) in capture.controls.iter().zip(&body) {
            raw.extend(removal_snapshot_frame_data(row).unwrap());raw.extend(bytes);
        }
        let genesis=parse_removal_genesis_data(raw.len() as u64,&"2".repeat(32),|at,out|{
            let at=at as usize;let n=out.len().min(raw.len()-at).min(13);out[..n].copy_from_slice(&raw[at..at+n]);Ok(n)
        }).unwrap();(genesis,selected,state,reference,raw)
    }
    #[test]
    fn completed_recovery_snapshot_rehome_requires_receipt_bound_originals_and_prefixes() {
        for prefix in [0,17,usize::MAX] {
            let (mut genesis,selected,state,reference,raw)=recovery_snapshot(prefix);
            let read=|at:u64,out:&mut[u8]|->Result<usize>{
                let at=at as usize;check(at<=raw.len(),"test-offset")?;
                let n=out.len().min(raw.len()-at).min(11);out[..n].copy_from_slice(&raw[at..at+n]);Ok(n)
            };
            let census=snapshot_census(&genesis,&reference,&selected,&state,REHOME_WORK,&mut {read}).unwrap();
            assert_eq!((census.indices.len(),census.attempts.len()),(4,1));
            let parsed=read_rehome_plan(&genesis,read).unwrap();assert_eq!(parsed.plan.invocations.len,3);
            assert_eq!(parsed.plan.recovery_controls.len(),4);
            for index in &parsed.plan.recovery_controls {
                let row=&genesis.controls_data()[*index];assert!(parsed.plan.selects_control_data(row));
                assert!(rehome_file_correspondence_data(row,row.identity_data(),row.flags_data(),row.digest_data()));
            }
            drop(parsed);
            let bad=RecoveryReferenceData::new_data(reference.stage_invocation_data(),reference.torn_invocation_data(),&"a".repeat(64)).unwrap();
            assert!(snapshot_census(&genesis,&bad,&selected,&state,REHOME_WORK,&mut {read}).is_err());
            assert!(snapshot_census(&genesis,&reference,&selected,&state,1,&mut {read}).is_err());
            let index=genesis.spans.controls.iter().position(|r|r.kind==5).unwrap();
            let saved=genesis.spans.controls[index].path.clone();
            genesis.spans.controls[index].path=saved.replace(&"3".repeat(32),&"9".repeat(32));
            assert!(read_rehome_plan(&genesis,read).is_err());
            genesis.spans.controls[index].path=saved;
            genesis.spans.controls[index].kind=0;
            assert!(read_rehome_plan(&genesis,read).is_err());
        }
    }
}
