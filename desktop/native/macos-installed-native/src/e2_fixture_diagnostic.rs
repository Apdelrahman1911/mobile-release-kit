//! Fixture-only, fixed DATA output. No finality, identity or admission authority.
#![forbid(unsafe_code)]
use std::fmt::{self,Write};
use crate::android_maintenance_diagnostic::{Diagnostic,Observation,NativeSnapshot};
pub const BYTES:usize=2048;
pub struct Buffer{pub bytes:[u8;BYTES],pub used:usize}
impl Write for Buffer {
    fn write_str(&mut self,s:&str)->fmt::Result{
        let end=self.used.checked_add(s.len()).filter(|n|*n<=BYTES).ok_or(fmt::Error)?;
        self.bytes[self.used..end].copy_from_slice(s.as_bytes());self.used=end;Ok(())
    }
}
impl Buffer {
    pub fn encode(case:&str,entered:bool,value:Diagnostic)->Option<Self>{
        Self::encode_at(case,entered,"worker-returned",value,None)
    }
    pub fn encode_at(case:&str,entered:bool,checkpoint:&str,value:Diagnostic,sample:Option<NativeSnapshot>)->Option<Self>{
        if !matches!(checkpoint,"worker-returned"|"client-unavailable"|"tail-received"|"peer-exited"|"drain-refused"|"transport-error"){return None;}
        if !matches!(case,"missing-b-refused"|"local-f-before-admission"|"genuine-tail-unregister"|"transport-only"){return None;}
        let mut out=Self{bytes:[0;BYTES],used:0};
        write!(out,"{{\"schemaVersion\":1,\"type\":\"mrk-fixture-maintenance-diagnostic-v1\",\"case\":\"{}\",\"clientCreated\":{},\"nativeFinalityQualified\":false,\"shippingQualified\":false,\"diagnostic\":{{\"first\":",case,entered).ok()?;
        out.observation(value.first)?;out.write_str(",\"cleanup\":").ok()?;out.observation(value.cleanup)?;
        out.write_str(",\"preClient\":").ok()?;
        if let Some(reason)=value.pre_client{write!(out,"\"{}\"",reason.name()).ok()?;}else{out.write_str("null").ok()?;}
        out.write_str("},\"checkpoint\":").ok()?;write!(out,"\"{}\",\"cachedNative\":",checkpoint).ok()?;
        out.native(sample)?;out.write_str("}\n").ok()?;Some(out)
    }
    fn observation(&mut self,value:Option<Observation>)->Option<()>{
        let Some(value)=value else{return self.write_str("null").ok();};
        write!(self,"{{\"phase\":\"{}\",\"failure\":\"{}\",\"native\":",value.phase.name(),value.failure_name()).ok()?;
        self.native(value.native)?;self.write_str("}").ok()
    }
    fn native(&mut self,sample:Option<NativeSnapshot>)->Option<()>{
        if let Some(n)=sample.filter(|n|n.valid()){
            write!(self,"{{\"firstCall\":{},\"firstCode\":{},\"calls\":{},\"returns\":{},\"callbacks\":{},\"callbackReturns\":{},\"nativeCall\":{},\"unknown\":{},\"slots\":[",n.first_call,n.first_code,n.calls,n.returns,n.callbacks,n.callback_returns,n.native_call,n.unknown).ok()?;
            for (i,slot) in n.slots.into_iter().enumerate(){if i!=0{self.write_str(",").ok()?;}write!(self,"{}",slot).ok()?;}
            self.write_str("]}").ok()?;
        }else{self.write_str("null").ok()?;}
        Some(())
    }
}
#[cfg(test)]mod tests{
    use super::*;use crate::android_maintenance_diagnostic::{Phase,NativeSnapshot};use crate::android_registration::Failure;
    #[test]fn fixed_fixture_record_preserves_zero_ordinal_without_claiming_finality(){
        let mut value=Diagnostic::default();value.record(Phase::ChallengeB,Failure::Native,Some(NativeSnapshot{first_call:0,first_code:22,calls:0,returns:0,callbacks:0,callback_returns:0,native_call:0,unknown:1,slots:[0;8]}));
        let out=Buffer::encode("missing-b-refused",true,value).unwrap();let text=std::str::from_utf8(&out.bytes[..out.used]).unwrap();
        assert!(out.used<BYTES);assert!(text.contains("\"firstCall\":0,\"firstCode\":22"));
        assert!(text.contains("\"nativeFinalityQualified\":false,\"shippingQualified\":false"));
        assert!(Buffer::encode("/private/user",true,value).is_none());
        println!("{}",text);
        let out=Buffer::encode_at("transport-only",true,"transport-error",value,value.first.unwrap().native).unwrap();
        println!("{}",std::str::from_utf8(&out.bytes[..out.used]).unwrap());
    }
}
