//! Complete canonical4052-byte native facts plus five actual Rust-return
//! observations. Decoding these bytes cannot construct a native key candidate.
use super::*;
pub const BYTES:usize=4052+20;
pub struct Receipt { facts:Facts, consumed:bool }
impl Receipt {
    #[cfg(feature="vault-helper")]
    pub(crate) fn observe(f:&Facts,consumed:bool)->Self {
        Self{facts:Facts{raw:f.raw,operation:f.operation,verified:f.verified,ffi_returned:f.ffi_returned,
            callback_panicked:f.callback_panicked,frame_retired:f.frame_retired},consumed}
    }
    pub fn facts(&self)->&Facts {&self.facts}
    pub fn effect_code(&self)->u32 {match self.facts.add_effect(){
        AddEffect::NotEntered=>0,AddEffect::Added=>1,AddEffect::Duplicate=>2,AddEffect::MayHaveAdded=>3}}
    pub fn settled(&self)->bool {
        let f=&self.facts;
        f.verified && f.native_run_returned() && f.verified_native_run_receipt()
            && f.custody()==Custody::Settled && !f.callback_panicked() && !f.native_exception()
            && f.process_interaction_restored() && f.raw.policy.role==3
            && (f.adapter_frame_retired() || self.consumed)
    }
    fn success_base(&self)->bool {
        self.settled() && !self.facts.stopped() && self.facts.ordinary_user_admitted()
            && self.facts.namespace_verified() && self.facts.original_item_verified()
            && self.facts.namespace_checkpoints_passed()==Some(NAMESPACE_CHECKPOINTS)
    }
    fn exact_item_call(&self,phase:u32,status:i32)->bool {
        self.facts.security_calls().is_some_and(|calls|{
            let mut item=calls.iter().filter(|r|matches!(r.phase,10|11));
            item.next().is_some_and(|r|r.phase==phase && r.entered==1 && r.returned==1 && r.status==status)
                && item.next().is_none()
        })
    }
    pub fn added(&self)->bool {
        self.facts.operation==Operation::AddOnly && self.success_base() && !self.consumed
            && self.facts.outcome()==Outcome::Added && self.facts.add_effect()==AddEffect::Added
            && self.exact_item_call(10,0)
    }
    pub fn candidate_consumed(&self)->bool {
        self.facts.operation==Operation::Lookup && self.success_base() && self.consumed
            && self.facts.outcome()==Outcome::Candidate && self.facts.add_effect()==AddEffect::NotEntered
            && self.facts.raw.flags&KEY_READY!=0 && self.exact_item_call(11,0)
    }
    fn valid(&self)->bool {
        let f=&self.facts;
        f.raw.operation==f.operation.raw() && f.raw.valid(false)
            && (!f.ffi_returned || f.raw.run_returned==1)
            && (!f.frame_retired || f.verified && f.custody()==Custody::Settled && !f.callback_panicked)
            && (!self.consumed || f.operation==Operation::Lookup && f.accepted(Outcome::Candidate)
                && f.raw.flags&KEY_READY!=0 && !f.frame_retired)
    }
}
struct Writer<'a>{b:&'a mut[u8],at:usize}
impl Writer<'_>{
    fn u32(&mut self,n:u32){self.b[self.at..self.at+4].copy_from_slice(&n.to_le_bytes());self.at+=4;}
    fn i32(&mut self,n:i32){self.b[self.at..self.at+4].copy_from_slice(&n.to_le_bytes());self.at+=4;}
}
struct Reader<'a>{b:&'a[u8],at:usize}
impl Reader<'_>{
    fn u32(&mut self)->u32{let n=u32::from_le_bytes(self.b[self.at..self.at+4].try_into().unwrap());self.at+=4;n}
    fn i32(&mut self)->i32{let n=i32::from_le_bytes(self.b[self.at..self.at+4].try_into().unwrap());self.at+=4;n}
}
pub fn encode(value:&Receipt,out:&mut[u8])->bool {
    if out.len()!=BYTES || !value.valid(){return false;}
    let mut w=Writer{b:out,at:0};let raw=&value.facts.raw;
    w.u32(raw.version);
    w.u32(raw.operation);
    w.u32(raw.outcome);
    w.u32(raw.effect);
    w.u32(raw.phase);
    w.u32(raw.failure_phase);
    w.u32(raw.flags);
    w.i32(raw.account_errno);
    w.u32(raw.keychain_status);
    w.u32(raw.slot_count);
    w.u32(raw.call_count);
    w.u32(raw.key_bytes);
    w.u32(raw.run_returned);
    for item in &raw.references { w.u32(item.reserved); w.u32(item.call_entered); w.u32(item.call_returned); w.u32(item.nonnull_returned); w.u32(item.release_entered); w.u32(item.release_returned); }
    for item in &raw.calls { w.u32(item.phase); w.u32(item.entered); w.u32(item.returned); w.i32(item.status); }
    w.u32(raw.directory_count);
    w.u32(raw.descriptor_count);
    w.u32(raw.namespace_entered);
    w.u32(raw.namespace_returned);
    w.u32(raw.namespace_passed);
    for item in &raw.descriptors { w.u32(item.reserved); w.u32(item.open_entered); w.u32(item.open_returned); w.u32(item.acquired); w.i32(item.open_errno); w.u32(item.close_entered); w.u32(item.close_returned); w.u32(item.closed); w.i32(item.close_result); w.i32(item.close_errno); }
    w.u32(raw.acl.snapshots_entered);
    w.u32(raw.acl.snapshots_returned);
    w.u32(raw.acl.snapshots_admitted);
    w.u32(raw.acl.entries);
    w.u32(raw.acl.filesec_init_entered);
    w.u32(raw.acl.filesec_init_returned);
    w.u32(raw.acl.filesec_acquired);
    w.u32(raw.acl.filesec_free_entered);
    w.u32(raw.acl.filesec_free_returned);
    w.u32(raw.acl.acl_export_entered);
    w.u32(raw.acl.acl_export_returned);
    w.u32(raw.acl.acl_acquired);
    w.u32(raw.acl.acl_free_entered);
    w.u32(raw.acl.acl_free_returned);
    w.u32(raw.acl.acl_freed);
    w.u32(raw.acl.qualifier_entered);
    w.u32(raw.acl.qualifier_returned);
    w.u32(raw.acl.qualifier_acquired);
    w.u32(raw.acl.qualifier_free_entered);
    w.u32(raw.acl.qualifier_free_returned);
    w.u32(raw.acl.qualifier_freed);
    w.u32(raw.native.entered);
    w.u32(raw.native.returned);
    w.u32(raw.native.last_call);
    w.u32(raw.native.last_returned);
    w.i32(raw.native.last_result);
    w.i32(raw.native.last_errno);
    w.u32(raw.native.failure_call);
    w.i32(raw.native.failure_result);
    w.i32(raw.native.failure_errno);
    w.u32(raw.policy.version);
    w.u32(raw.policy.kind);
    w.u32(raw.policy.role);
    w.u32(raw.policy.entered);
    w.u32(raw.policy.scope_admitted);
    w.u32(raw.policy.original_valid);
    w.u32(raw.policy.original_value);
    w.u32(raw.policy.installed);
    w.u32(raw.policy.restore_due);
    w.u32(raw.policy.restored);
    w.u32(raw.policy.failed);
    w.u32(raw.policy.first_failure);
    w.u32(raw.policy.finished);
    w.u32(raw.policy.callback_refused);
    w.u32(raw.policy.cleanup_refused);
    w.u32(raw.policy.namespace_entered);
    w.u32(raw.policy.namespace_returned);
    w.u32(raw.policy.namespace_completed);
    for item in &raw.policy.calls { w.u32(item.entered); w.u32(item.returned); w.u32(item.refused); w.u32(item.exception); w.i32(item.status); w.u32(item.value); w.u32(item.value_valid); }
    for fact in [value.facts.verified,value.facts.ffi_returned,value.facts.callback_panicked,value.facts.frame_retired,value.consumed] {w.u32(u32::from(fact));}
    w.at==BYTES
}
pub fn decode(bytes:&[u8],operation:Operation)->Option<Receipt>{
    if bytes.len()!=BYTES{return None;}
    let mut r=Reader{b:bytes,at:0};
    let raw=RawResult { version: r.u32(), operation: r.u32(), outcome: r.u32(), effect: r.u32(), phase: r.u32(), failure_phase: r.u32(), flags: r.u32(), account_errno: r.i32(), keychain_status: r.u32(), slot_count: r.u32(), call_count: r.u32(), key_bytes: r.u32(), run_returned: r.u32(), references: std::array::from_fn(|_| ReferenceObservation { reserved: r.u32(), call_entered: r.u32(), call_returned: r.u32(), nonnull_returned: r.u32(), release_entered: r.u32(), release_returned: r.u32() }), calls: std::array::from_fn(|_| CallObservation { phase: r.u32(), entered: r.u32(), returned: r.u32(), status: r.i32() }), directory_count: r.u32(), descriptor_count: r.u32(), namespace_entered: r.u32(), namespace_returned: r.u32(), namespace_passed: r.u32(), descriptors: std::array::from_fn(|_| DescriptorObservation { reserved: r.u32(), open_entered: r.u32(), open_returned: r.u32(), acquired: r.u32(), open_errno: r.i32(), close_entered: r.u32(), close_returned: r.u32(), closed: r.u32(), close_result: r.i32(), close_errno: r.i32() }), acl: AclObservation { snapshots_entered: r.u32(), snapshots_returned: r.u32(), snapshots_admitted: r.u32(), entries: r.u32(), filesec_init_entered: r.u32(), filesec_init_returned: r.u32(), filesec_acquired: r.u32(), filesec_free_entered: r.u32(), filesec_free_returned: r.u32(), acl_export_entered: r.u32(), acl_export_returned: r.u32(), acl_acquired: r.u32(), acl_free_entered: r.u32(), acl_free_returned: r.u32(), acl_freed: r.u32(), qualifier_entered: r.u32(), qualifier_returned: r.u32(), qualifier_acquired: r.u32(), qualifier_free_entered: r.u32(), qualifier_free_returned: r.u32(), qualifier_freed: r.u32() }, native: NativeCallObservation { entered: r.u32(), returned: r.u32(), last_call: r.u32(), last_returned: r.u32(), last_result: r.i32(), last_errno: r.i32(), failure_call: r.u32(), failure_result: r.i32(), failure_errno: r.i32() }, policy: ProcessInteractionObservation { version: r.u32(), kind: r.u32(), role: r.u32(), entered: r.u32(), scope_admitted: r.u32(), original_valid: r.u32(), original_value: r.u32(), installed: r.u32(), restore_due: r.u32(), restored: r.u32(), failed: r.u32(), first_failure: r.u32(), finished: r.u32(), callback_refused: r.u32(), cleanup_refused: r.u32(), namespace_entered: r.u32(), namespace_returned: r.u32(), namespace_completed: r.u32(), calls: std::array::from_fn(|_| InteractionCallObservation { entered: r.u32(), returned: r.u32(), refused: r.u32(), exception: r.u32(), status: r.i32(), value: r.u32(), value_valid: r.u32() }) } };
    let observations:[u32;5]=std::array::from_fn(|_|r.u32());
    if r.at!=BYTES || observations.iter().any(|v|*v>1){return None;}
    let value=Receipt{facts:Facts{raw,operation,verified:observations[0]==1,ffi_returned:observations[1]==1,
        callback_panicked:observations[2]==1,frame_retired:observations[3]==1},consumed:observations[4]==1};
    value.valid().then_some(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_scalar_transport_is_canonical_and_never_infers_return_or_consumption(){
        let f=Facts{raw:RawResult::empty(Operation::Lookup,10),operation:Operation::Lookup,
            verified:true,ffi_returned:false,callback_panicked:false,frame_retired:false};
        let value=Receipt{facts:f,consumed:false};let mut b=[0;BYTES];assert!(encode(&value,&mut b));
        let read=decode(&b,Operation::Lookup).unwrap();assert!(!read.settled());assert!(!read.candidate_consumed());
        let mut copy=[0;BYTES];assert!(encode(&read,&mut copy));assert_eq!(copy,b);
        assert!(decode(&b,Operation::AddOnly).is_none());assert!(decode(&b[..BYTES-1],Operation::Lookup).is_none());
        for at in [0,4,4056,4064,4068]{let mut bad=b;bad[at]^=128;assert!(decode(&bad,Operation::Lookup).is_none());}
        let mut forged=b;forged[4068..4072].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode(&forged,Operation::Lookup).is_none());
    }
}
