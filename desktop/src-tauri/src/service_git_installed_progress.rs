//! Nonshipping, bounded DATA only. No Entry, native owner, source, identifier,
//! callback or operation authority is reachable from this object.
use super::{InstalledNativeFailure, NativeLink, Phase};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

#[derive(Default)]
pub(crate) struct ApplyProgress {
    mask: AtomicU32,
    first_error: AtomicU8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Facts {
    mask: u32,
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
impl ApplyProgress {
    pub(crate) fn job(&self, job: Job, point: Point) {
        let index=match job {Job::Publisher=>0,Job::Host=>1,Job::Open=>2,Job::Preparing=>3,
            Job::Candidate=>4,Job::Finish=>5,Job::RetireUse=>6,Job::FinishPublisher=>7};
        let offset=match point {Point::Registered=>0,Point::Entered=>1,Point::JoinReturned=>2};
        self.mask.fetch_or(1 << (3*index+offset),Ordering::Release);
    }
    pub(crate) fn boundary(&self, boundary: Boundary) {
        let offset=match boundary {Boundary::StartupEntered=>24,Boundary::HostTicketRequested=>25,
            Boundary::HostTicketReturned=>26,Boundary::ReadyHandoffRequested=>27,Boundary::ReadyHandoffReturned=>28,
            Boundary::FinalizeEntered=>29,Boundary::RetireEntered=>30,Boundary::OwnerArmed=>31};
        self.mask.fetch_or(1 << offset,Ordering::Release);
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
        // Separate closed atomics, not a coherent owner status or a join proof.
        use InstalledNativeFailure as F;
        let mask=self.mask.load(Ordering::Acquire);
        let first_error=match self.first_error.load(Ordering::Acquire) {1=>Some(F::CleanupUnknown),2=>Some(F::ContextChanged),
            3=>Some(F::Busy),4=>Some(F::Cancelled),5=>Some(F::ShuttingDown),6=>Some(F::QueryTimeout),
            7=>Some(F::GitLocalRefused),8=>Some(F::InvalidRequest),9=>Some(F::ProtocolError),10=>Some(F::Other),_=>None};
        Facts {mask,first_error}
    }
}
impl NativeLink {
    pub(crate) fn installed_apply_progress(&self) -> Option<&ApplyProgress> {
        (self.phase==Phase::Apply && !self.is_remote()).then_some(self.entry.installed_apply_progress.as_ref())
    }
}
