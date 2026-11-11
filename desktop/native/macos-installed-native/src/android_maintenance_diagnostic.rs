//! Fixed comparison DATA only. Never an admission, native read or retirement proof.
#![forbid(unsafe_code)]
use crate::android_registration::Failure;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Phase { Begin, ChallengeA, Watch, ChallengeB, Drain, Receive, Receipt, Tail, Cleanup }
impl Phase {
    pub fn name(self)->&'static str { match self {
        Self::Begin=>"begin",Self::ChallengeA=>"A",Self::Watch=>"watch",Self::ChallengeB=>"B",
        Self::Drain=>"drain",Self::Receive=>"receive",Self::Receipt=>"receipt",Self::Tail=>"tail",Self::Cleanup=>"cleanup",
    }}
}
/// Explicit allowlist omits peer/account IDs, wire contents and native text.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct NativeSnapshot {
    pub first_call:u32,pub first_code:i32,pub calls:u32,pub returns:u32,
    pub callbacks:u32,pub callback_returns:u32,pub native_call:u32,pub unknown:u32,pub slots:[u32;8],
}
impl NativeSnapshot {
    pub fn valid(self)->bool {
        self.calls<=400_000 && self.returns<=self.calls && self.calls-self.returns<=1
            && self.callbacks<=400_000 && self.callback_returns<=self.callbacks
            && self.callbacks-self.callback_returns<=1 && self.native_call<=1 && self.unknown<=1
            && self.first_call<=self.calls && self.slots.iter().all(|slot|*slot<=5)
            // C can report an error before the first native entry (ordinal0).
            && (self.first_code==0 && self.first_call==0 || (1..=4095).contains(&self.first_code))
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Observation {pub phase:Phase,pub failure:Failure,pub native:Option<NativeSnapshot>}
impl Observation {
    pub fn failure_name(self)->&'static str {match self.failure {
        Failure::Unavailable=>"unavailable",Failure::Bounds=>"bounds",Failure::Binding=>"binding",
        Failure::Sequence=>"sequence",Failure::Busy=>"busy",Failure::Stopped=>"stopped",
        Failure::Native=>"native",Failure::Unknown=>"unknown",
    }}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum PreClientFailure { SourceWork, IdentityCheck, WorkCut, ProbePrerequisite }
impl PreClientFailure {
    pub fn name(self)->&'static str {match self {
        Self::SourceWork=>"source-work",Self::IdentityCheck=>"identity-check",Self::WorkCut=>"work-cut",Self::ProbePrerequisite=>"probe-prerequisite",
    }}
}
/// First original failure and first cleanup failure are independently immutable.
/// None means unavailable, never a successful exchange or known cleanup.
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct Diagnostic {pub first:Option<Observation>,pub cleanup:Option<Observation>,pub pre_client:Option<PreClientFailure>}
impl Diagnostic {
    pub fn before_client(&mut self,reason:PreClientFailure){
        if self.pre_client.is_none(){self.pre_client=Some(reason);}
    }
    pub(crate) fn record(&mut self,phase:Phase,failure:Failure,native:Option<NativeSnapshot>) {
        let observation=Observation{phase,failure,native:native.filter(|value|value.valid())};
        if self.first.is_none(){self.first=Some(observation);}
        if phase==Phase::Cleanup && self.cleanup.is_none(){self.cleanup=Some(observation);}
    }
}
const _:()=assert!(std::mem::size_of::<Diagnostic>()<=256);
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot()->NativeSnapshot {NativeSnapshot{first_call:7,first_code:71,calls:8,returns:8,
        callbacks:1,callback_returns:1,native_call:0,unknown:1,slots:[4;8]}}
    #[test] fn identity_refusal_survives_cleanup_without_claiming_client_entry(){
        let mut value=Diagnostic::default();value.before_client(PreClientFailure::IdentityCheck);
        value.record(Phase::Cleanup,Failure::Unknown,None);value.before_client(PreClientFailure::WorkCut);
        assert_eq!(value.pre_client,Some(PreClientFailure::IdentityCheck));
        assert_eq!(value.first.unwrap().phase,Phase::Cleanup);
    }
    #[test] fn first_failure_survives_cleanup_and_repeated_projection(){
        let mut value=Diagnostic::default();value.record(Phase::ChallengeB,Failure::Binding,Some(snapshot()));
        let first=value.first;value.record(Phase::Cleanup,Failure::Unknown,None);
        value.record(Phase::Tail,Failure::Native,None);value.record(Phase::Cleanup,Failure::Stopped,Some(snapshot()));
        assert_eq!(value.first,first);assert_eq!(value.cleanup.unwrap().failure,Failure::Unknown);
        assert_eq!(value.first.unwrap().phase,Phase::ChallengeB);assert!(value.cleanup.unwrap().native.is_none());
    }
    #[test] fn pre_peer_and_cleanup_only_failures_are_distinct_and_missing_is_not_success(){
        let mut before=Diagnostic::default();assert_eq!(before,Diagnostic{first:None,cleanup:None,pre_client:None});
        before.record(Phase::Begin,Failure::Unavailable,None);assert_eq!(before.first.unwrap().phase.name(),"begin");
        assert!(before.first.unwrap().native.is_none());assert!(before.cleanup.is_none());
        let mut cleanup=Diagnostic::default();cleanup.record(Phase::Cleanup,Failure::Unknown,Some(snapshot()));
        assert_eq!(cleanup.first,cleanup.cleanup);assert_ne!(before,cleanup);
    }
    #[test] fn ordinal_zero_native_error_is_retained_and_ordinal_is_not_method_code(){
        let before_entry=NativeSnapshot{first_call:0,first_code:22,calls:0,returns:0,callbacks:0,
            callback_returns:0,native_call:0,unknown:1,slots:[0;8]};
        assert!(before_entry.valid());
        let mut value=Diagnostic::default();value.record(Phase::Begin,Failure::Native,Some(before_entry));
        assert_eq!(value.first.unwrap().native,Some(before_entry));
        assert!(!NativeSnapshot{first_call:2,calls:1,returns:1,..before_entry}.valid());
        assert!(!NativeSnapshot{first_call:1,calls:1,returns:1,first_code:0,..before_entry}.valid());
    }
    #[test] fn invalid_native_data_is_unavailable_without_erasing_rust_failure(){
        for invalid in [NativeSnapshot{returns:9,..snapshot()},NativeSnapshot{first_code:-1,..snapshot()},
            NativeSnapshot{slots:[6;8],..snapshot()},NativeSnapshot{callbacks:400_001,..snapshot()}]{
            let mut value=Diagnostic::default();value.record(Phase::Watch,Failure::Native,Some(invalid));
            assert_eq!(value.first.unwrap().failure,Failure::Native);assert!(value.first.unwrap().native.is_none());
        }
    }
}
