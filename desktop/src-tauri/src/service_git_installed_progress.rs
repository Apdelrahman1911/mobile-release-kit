//! Nonshipping, bounded DATA only. No Entry, native owner, source, identifier,
//! callback or operation authority is reachable from this object.
use super::{InstalledNativeFailure, NativeLink, Phase};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct ApplyProgress {
    // One original word keeps these two closed progress masks at the same
    // observation instant. It still carries no coherent native owner status.
    milestones: AtomicU64,
    first_error: AtomicU8,
}
// Shared only with the original OwnerState. This contains bounded DATA, never
// an Entry, NativeLink, callback or native owner. Central failure recording can
// freeze the category without taking another application lock.
pub(crate) struct FailureLatch {
    first: std::sync::OnceLock<InstalledNativeFailure>,
    progress: Option<std::sync::Arc<ApplyProgress>>,
}
impl FailureLatch {
    pub(crate) fn new(progress: Option<std::sync::Arc<ApplyProgress>>) -> Self {
        Self { first: std::sync::OnceLock::new(), progress }
    }
    pub(crate) fn capture(&self, code: &str) -> InstalledNativeFailure {
        let category = *self.first.get_or_init(|| InstalledNativeFailure::from_code(code));
        if let Some(progress) = &self.progress { progress.first_error(category); }
        category
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Facts {
    mask: u32,
    control_mask: u32,
    first_error: Option<InstalledNativeFailure>,
}
#[derive(Clone, Copy)]
pub(crate) enum Job { Publisher, Host, Open, Preparing, Candidate, Finish, RetireUse, FinishPublisher }
#[derive(Clone, Copy)]
pub(crate) enum Point { Registered, Entered, JoinReturned }
#[derive(Clone, Copy)]
pub(crate) enum Boundary {
    StartupEntered, HostTicketRequested, HostTicketReturned,
    ReadyHandoffRequested, ReadyHandoffReturned, FinalizeEntered,
    RetireEntered, OwnerArmed,
}
// Closed original control milestones. Requested/returned bits include errors
// unless named Ok; none proves native entry, coherent state or finality.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Control {
    StartupReturnedOk=0, InspectionRegistered=1, InspectionWorkerReleased=2,
    GitInspectionEntered=3, AclArmRequested=4, AclArmReturned=5,
    RuntimeResolveRequested=6, RuntimeResolveReturned=7,
    SourceInspectRequested=8, SourceInspectReturned=9, RequestStoredCurrentOk=10,
    InspectionJoinReturned=11, InspectionOkAccepted=12,
    ChildSpawnRequested=13, ChildSpawnReturned=14, RequestWriteReturned=15,
    ReadyParsed=16, WriterReadyReturned=17, WriterPostSent=18, PostReceived=19,
    NativePostRequested=20, NativePostReturned=21,
    SourcePostRequested=22, SourcePostReturned=23, PostJoinReturned=24,
    PostAckRequested=25, WriterPostReplyReturned=26,
    GoClaimRequested=27, GoClaimReturnedOk=28, GoWriteReturned=29,
    CandidateRowValidated=30, CandidateReceiverReturned=31,
}
impl ApplyProgress {
    pub(crate) fn control(&self, point: Control) {
        self.milestones.fetch_or(1u64 << (32+point as u8),Ordering::Release);
    }
    pub(crate) fn job(&self, job: Job, point: Point) {
        let index=match job {Job::Publisher=>0,Job::Host=>1,Job::Open=>2,Job::Preparing=>3,
            Job::Candidate=>4,Job::Finish=>5,Job::RetireUse=>6,Job::FinishPublisher=>7};
        let offset=match point {Point::Registered=>0,Point::Entered=>1,Point::JoinReturned=>2};
        self.milestones.fetch_or(1u64 << (3*index+offset),Ordering::Release);
    }
    pub(crate) fn boundary(&self, boundary: Boundary) {
        let offset=match boundary {Boundary::StartupEntered=>24,Boundary::HostTicketRequested=>25,
            Boundary::HostTicketReturned=>26,Boundary::ReadyHandoffRequested=>27,Boundary::ReadyHandoffReturned=>28,
            Boundary::FinalizeEntered=>29,Boundary::RetireEntered=>30,Boundary::OwnerArmed=>31};
        self.milestones.fetch_or(1u64 << offset,Ordering::Release);
    }
    pub(crate) fn first_error(&self, category: InstalledNativeFailure) {
        // The caller already froze this SAME category under OwnerState. This
        // pure one-shot publication cannot wait on Document/Entry/Record.
        use InstalledNativeFailure as F;
        let byte=match category {F::CleanupUnknown=>1,F::ContextChanged=>2,F::Busy=>3,F::Cancelled=>4,
            F::ShuttingDown=>5,F::QueryTimeout=>6,F::GitLocalRefused=>7,F::InvalidRequest=>8,F::ProtocolError=>9,F::Other=>10};
        let _=self.first_error.compare_exchange(0,byte,Ordering::Release,Ordering::Relaxed);
    }
    pub(crate) fn snapshot(&self) -> Facts {
        // One atomic snapshot for both masks. The first error remains separate
        // closed DATA; neither observation is owner status or a join proof.
        use InstalledNativeFailure as F;
        let milestones=self.milestones.load(Ordering::Acquire);
        let mask=milestones as u32;
        let control_mask=(milestones>>32) as u32;
        let first_error=match self.first_error.load(Ordering::Acquire) {1=>Some(F::CleanupUnknown),2=>Some(F::ContextChanged),
            3=>Some(F::Busy),4=>Some(F::Cancelled),5=>Some(F::ShuttingDown),6=>Some(F::QueryTimeout),
            7=>Some(F::GitLocalRefused),8=>Some(F::InvalidRequest),9=>Some(F::ProtocolError),10=>Some(F::Other),_=>None};
        Facts {mask,control_mask,first_error}
    }
}
#[cfg(all(test,debug_assertions,feature="desktop-shell",feature="custom-protocol",feature="macos-installed-observation",
    not(feature="development-runtime"),not(feature="ubuntu-runtime-publisher"),not(feature="macos-installed-installer"),
    target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) fn snapshot_pair_contract_data() {
    // This standalone object has no Entry/NativeLink/owner. Complementary
    // halves exercise same-word reads while another DATA thread writes; no
    // scheduler timing, native work, source, identifier or callback is adopted.
    let data=std::sync::Arc::new(ApplyProgress::default());
    data.milestones.store((u32::MAX as u64)<<32,Ordering::Release);
    let writer=data.clone();
    let joined=std::thread::spawn(move || {
        for mask in 0..4096u32 {
            writer.milestones.store((((!mask) as u64)<<32)|(mask as u64),Ordering::Release);
        }
    });
    for _ in 0..8192 {
        let facts=data.snapshot();
        assert_eq!(facts.control_mask,!facts.mask);
        assert_eq!(facts.first_error,None);
    }
    joined.join().expect("the inert progress writer returned");
    assert_eq!(data.snapshot().mask,4095);
}
impl NativeLink {
    pub(crate) fn installed_apply_progress(&self) -> Option<&ApplyProgress> {
        (self.phase==Phase::Apply && !self.is_remote()).then_some(self.entry.installed_apply_progress.as_ref())
    }
    pub(crate) fn installed_apply_progress_data(&self) -> Option<std::sync::Arc<ApplyProgress>> {
        (self.phase==Phase::Apply && !self.is_remote()).then(||self.entry.installed_apply_progress.clone())
    }
}
